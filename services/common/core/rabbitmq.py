
import pika
import json
import logging
import time
import threading

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from .secrets import get_rabbitmq_url

logger = logging.getLogger(__name__)

class RabbitMQClient:
    def __init__(self, url=None):
        self.url = url or get_rabbitmq_url()
        self.connection = None
        self.channel = None
        self._closing = False
        
    def connect(self):
        """Connect to RabbitMQ with retries"""
        retries = 5
        while retries > 0:
            try:
                params = pika.URLParameters(self.url)
                self.connection = pika.BlockingConnection(params)
                self.channel = self.connection.channel()
                logger.info("✅ Connected to RabbitMQ")
                return self.connection
            except Exception as e:
                logger.warning(f"⚠️ RabbitMQ Connection Failed: {e}. Retrying ({retries} left)...")
                retries -= 1
                time.sleep(5)
        raise Exception("Could not connect to RabbitMQ")

    def publish(self, queue_name, message: dict):
        """Publish a message to a queue"""
        if not self.connection or self.connection.is_closed:
            self.connect()
            
        try:
            self.channel.queue_declare(queue=queue_name, durable=True)
            self.channel.basic_publish(
                exchange='',
                routing_key=queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                )
            )
            logger.info(f"📨 Published to {queue_name}: {message}")
        except Exception as e:
            logger.error(f"❌ Failed to publish to {queue_name}: {e}")
            # Try reconnecting once
            try:
                self.connect()
                self.channel.queue_declare(queue=queue_name, durable=True)
                self.channel.basic_publish(
                    exchange='',
                    routing_key=queue_name,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
            except Exception as e2:
                logger.error(f"❌ Retry Publish failed: {e2}")

    def consume(self, queue_name, callback):
        """Start consuming messages from a queue in a blocking way (run in thread)"""
        if not self.connection or self.connection.is_closed:
            self.connect()
            
        self.channel.queue_declare(queue=queue_name, durable=True)
        self.channel.basic_qos(prefetch_count=1)
        
        def on_message(ch, method, properties, body):
            try:
                data = json.loads(body)
                logger.info(f"📥 [RABBITMQ] Received from '{queue_name}' | Routing Key: '{method.routing_key}' | Body: {json.dumps(data, indent=2)}")
                callback(data)
                ch.basic_ack(delivery_tag=method.delivery_tag)
                logger.info(f"✅ [RABBITMQ] Processed & Acked message from '{queue_name}'")
            except Exception as e:
                logger.error(f"❌ [RABBITMQ] Error processing message from '{queue_name}': {e}", exc_info=True)
                # Potentially nack if you want retry, but be careful of loop
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        self.channel.basic_consume(queue=queue_name, on_message_callback=on_message)
        logger.info(f"🎧 [RABBITMQ] Listening on queue '{queue_name}'...")
        try:
            self.channel.start_consuming()
        except Exception as e:
            if not self._closing:
                logger.error(f"❌ Consumption interrupted: {e}")

    def close(self):
        self._closing = True
        if self.connection and not self.connection.is_closed:
            self.connection.close()

    def start_consumer_thread(self, queue_name, callback):
        """Helper to run consumer in a background thread"""
        t = threading.Thread(target=self.consume, args=(queue_name, callback), daemon=True)
        t.start()
        return t
