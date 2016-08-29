# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/aws_config"
require "logstash/timestamp"
require "time"
require "tmpdir"
require "stud/interval"
require "stud/temporary"

# Stream events from ClougWatch Logs streams.
#
# Primarily designed to pull logs from Lambda's which are logging to
# CloudWatch Logs. Specify a log group, and this plugin will scan
# all log streams in that group, and pull in any new log events.
#
class LogStash::Inputs::CloudWatch_Logs < LogStash::Inputs::Base
  include LogStash::PluginMixins::AwsConfig::V2

  config_name "cloudwatch_logs"

  default :codec, "plain"

  # Log group to pull logs from for this plugin. Will pull in all
  # streams inside of this log group.
  config :log_group, :validate => :string, :required => true

  # Where to write the since database (keeps track of the date
  # the last stream was checked from cwlogs).
  config :state_table, :validate => :string, :default => "cloudwatchlogs"

  # Interval to wait between to check the file list again after a run is finished.
  # Value is in seconds.
  config :interval, :validate => :number, :default => 60

  # Expunge logstreams that haven't been written to in greater than :value seconds
  config :expunge, :validate => :number, :default => -1
  # def register
  public
  def register
    require "digest/md5"
    require "aws-sdk"

    @logger.info("Registering cloudwatch_logs input", :log_group => @log_group)

    @cloudwatch = Aws::CloudWatchLogs::Client.new(aws_options_hash)
    @ddb = Aws::DynamoDB::Client.new(aws_options_hash)
  end #def register

  # def run
  public
  def run(queue)
    while !stop?
      process_group(queue)
      Stud.stoppable_sleep(@interval)
    end
  end # def run

  # def list_new_streams
  public
  def list_new_streams(token = nil, objects = [])
    params = {
        :log_group_name => @log_group,
        :order_by => "LastEventTime",
        :descending => false
    }

    if token != nil
      params[:next_token] = token
    else
      @logger.info("Enumerating log group", :log_group => @log_group)
    end

    begin
      streams = @cloudwatch.describe_log_streams(params)
    rescue Aws::CloudWatchLogs::Errors::ThrottlingException
      sleep(1)
      retry
    end
    objects.push(*streams.log_streams)
    if streams.next_token == nil
      @logger.debug("CloudWatch Logs hit end of tokens for streams")
      objects
    else
      @logger.debug("CloudWatch Logs calling list_new_streams again on token", :token => streams.next_token)
      list_new_streams(streams.next_token, objects)
    end

  end # def list_new_streams

  # def process_log
  private
  def process_log(queue, log, stream)

    @codec.decode(log.message.to_str) do |event|
      event[LogStash::Event::TIMESTAMP] = parse_time(log.timestamp)
      event["[cloudwatch][ingestion_time]"] = parse_time(log.ingestion_time)
      event["[cloudwatch][log_group]"] = @log_group
      event["[cloudwatch][log_stream]"] = stream.log_stream_name
      decorate(event)

      queue << event
    end
  end
  # def process_log

  # def parse_time
  private
  def parse_time(data)
    LogStash::Timestamp.at(data.to_i / 1000, (data.to_i % 1000) * 1000)
  end # def parse_time

  # def process_group
  public
  def process_group(queue)
    objects = list_new_streams

    current_window = DateTime.now.strftime('%Q')

    objects.each do |stream|
      resp = @ddb.get_item({
        table_name: @state_table,
        key: {
          logGroup: @log_group,
          logStreamName: stream.log_stream_name,
        }
      })
      if resp.item
        @logger.debug("DynamoDB State", :item => resp.item )
        # do something with resp.item state
      else
        @logger.debug("Empty State", :item => resp.item )
        # create a new state
      end
      rescues = 0
      begin
        last_event = nil
        whence = stream.last_event_timestamp.to_i or stream.creation_time.to_i
        if @expunge > 0 and Time.now.to_i - whence > @expunge
            @logger.info("Expunging stream", :log_group_name => @log_group, :log_stream_name => stream.log_stream_name)
            # We delete state first, as worst case is we'll replay the stream, whereas in the
            # reverse, we could delete the stream and have state that never gets expunged.
            @ddb.delete_item({
              table_name: @state_table,
              key: {
                logGroup: @log_group,
                logStreamName: stream.log_stream_name,
              }
            })
            @cloudwatch.delete_log_stream({
              :log_group_name => @log_group,
              :log_stream_name => stream.log_stream_name,
            })
            next
        end
        if (resp.item or {})["last_read"].to_i == stream.last_event_timestamp.to_i
          @logger.debug("No new data in stream", :log_group_name => @log_group, :log_stream_name => stream.log_stream_name)
          next
        end
        @cloudwatch.get_log_events({
          :log_group_name => @log_group,
          :log_stream_name => stream.log_stream_name,
          :start_from_head => true,
          :start_time => (resp.item.nil?) ? 1 : resp.item["last_read"].to_i,
        }).each do | page |
          (page.events or []).each do | event |
            process_log(queue, event, stream)
            last_event = event
          end
          if last_event
            @ddb.put_item({
              table_name: @state_table,
              item: {
                logGroup: @log_group,
                logStreamName: stream.log_stream_name,
                last_read: last_event.timestamp,
              }
            })
            resp.item = (resp.item or {}).update({ last_read: last_event.timestamp})
          end
        end
      rescue Aws::CloudWatchLogs::Errors::ThrottlingException
        # We got throttled paginating a log - we'll have recorded our LKG, we'll resume it
        # the next time thorugh.
        rescues += 1
        sleep(rescues ** 0.5)
        retry
      end
    end

  end # def process_group

end # class LogStash::Inputs::CloudWatch_Logs
