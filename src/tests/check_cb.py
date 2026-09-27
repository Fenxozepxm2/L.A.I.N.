import asyncio
from sqlalchemy import text
from repository.database import Async_fabric_make


async def check_conn_db():
    print("Проверка подключения к PostgreSQL...")


    try:
        async with Async_fabric_make() as connect:
            result = await connect.execute(text("SELECT version();"))
            db_version = result.scalar()
            print("✅ Подключение успешно установлено!")
            print(f"Версия базы данных: {db_version}")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    asyncio.run(check_conn_db())