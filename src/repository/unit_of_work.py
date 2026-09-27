from repository.database import Async_fabric_make
from repository.repos import HostRepository

class UnitOfWork:
    def __init__(self):
        self.session_factory = Async_fabric_make

    async def __aenter__(self):
        # При входе в контекст автоматически создаётся сессия на весь рабочий цикл
        self.session = self.session_factory()
        
        # Сюда привязываем репозитории, передавая им эту сессию
        self.vacancies = HostRepository(self.session)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # При выходе сессия автоматически закрывается
        if exc_type is not None:
            await self.session.rollback()  # Если была ошибка — откатываем
        else:
            await self.session.commit()    # Если всё ок — сохраняем
        await self.session.close()
