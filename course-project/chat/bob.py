import asyncio

from utils import bob_client, show, prompt, read_message_from_stdin


async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Alice (can be multiple messages)
        data = await reader.read(1024)
        if not data:
            break

        # {DECRYPT HERE}
        message = data.decode()

        show(message)
        prompt()


async def send(writer):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        data = message.strip().encode()

        # Send message
        writer.write(data)

        prompt()
        await writer.drain()


async def init_connection():
    reader, writer = await bob_client()
    print("Connected to Alice!")
    prompt()

    # INITIAL EXCHANGE HERE

    await asyncio.gather(receive(reader), send(writer))


if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
