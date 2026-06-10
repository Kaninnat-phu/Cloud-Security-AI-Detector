import boto3
import asyncio
import aiofiles
import json
import time
from datetime import datetime, timezone
from dotenv import load_dotenv
import os

load_dotenv()

class LogIngestionEngine:
    def __init__(self):
        self.client = boto3.client('logs', region_name=os.getenv('AWS_REGION'))
        self.cloudtrail = boto3.client('cloudtrail', region_name=os.getenv('AWS_REGION'))
        self.event_queue = asyncio.Queue()
        self.log_groups = {
            'vpc_flows': os.getenv('VPC_FLOW_LOG_GROUP'),
            'app_logs': os.getenv('APP_LOG_GROUP'),
        }
        self.last_timestamp = {}

    def get_start_time(self, source):
        if source in self.last_timestamp:
            return self.last_timestamp[source]
        return int((time.time() - 300) * 1000)

    async def stream_cloudwatch_logs(self, source, log_group):
        print(f"[INGESTION] Streaming {source} from {log_group}")
        while True:
            try:
                start_time = self.get_start_time(source)
                streams = self.client.describe_log_streams(
                    logGroupName=log_group,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=5
                )
                for stream in streams.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    response = self.client.get_log_events(
                        logGroupName=log_group,
                        logStreamName=stream_name,
                        startTime=start_time,
                        startFromHead=False
                    )
                    for event in response.get('events', []):
                        await self.event_queue.put({
                            'source': source,
                            'timestamp': event['timestamp'],
                            'message': event['message'],
                            'stream': stream_name,
                            'ingested_at': datetime.now(timezone.utc).isoformat()
                        })
                        self.last_timestamp[source] = event['timestamp'] + 1
            except Exception as e:
                print(f"[ERROR] {source}: {e}")
            await asyncio.sleep(30)

    async def stream_cloudtrail(self):
        print("[INGESTION] Streaming CloudTrail events")
        while True:
            try:
                response = self.cloudtrail.lookup_events(
                    StartTime=datetime.fromtimestamp(time.time() - 300, tz=timezone.utc),
                    MaxResults=50
                )
                for event in response.get('Events', []):
                    await self.event_queue.put({
                        'source': 'cloudtrail',
                        'timestamp': int(event['EventTime'].timestamp() * 1000),
                        'message': json.dumps({
                            'eventName': event.get('EventName'),
                            'username': event.get('Username'),
                            'sourceIP': event.get('SourceIPAddress', 'unknown'),
                            'resources': event.get('Resources', []),
                            'errorCode': event.get('ErrorCode', None)
                        }),
                        'ingested_at': datetime.now(timezone.utc).isoformat()
                    })
            except Exception as e:
                print(f"[ERROR] cloudtrail: {e}")
            await asyncio.sleep(30)

    async def log_events(self):
        os.makedirs(os.path.expanduser('~/security-detector/logs'), exist_ok=True)
        log_file = os.path.expanduser('~/security-detector/logs/events.jsonl')
        print(f"[INGESTION] Logging events to {log_file}")
        while True:
            event = await self.event_queue.get()
            print(f"[EVENT] {event['source']} | {event['message'][:80]}")
            async with aiofiles.open(log_file, 'a') as f:
                await f.write(json.dumps(event) + '\n')

    async def run(self):
        print("[INGESTION] Starting all log streams...")
        await asyncio.gather(
            self.stream_cloudtrail(),
            self.stream_cloudwatch_logs('vpc_flows', self.log_groups['vpc_flows']),
            self.stream_cloudwatch_logs('app_logs', self.log_groups['app_logs']),
            self.log_events()
        )

if __name__ == "__main__":
    engine = LogIngestionEngine()
    asyncio.run(engine.run())
