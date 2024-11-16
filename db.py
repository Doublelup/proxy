import sqlite3
from threading import Lock


class DB:
    def __init__(self, dbname:str):
        self._name = dbname
        self._lock = Lock()
        self._connection = sqlite3.connect(dbname, check_same_thread=False)
        cursor = self._connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            hash TEXT not null,
            created_at timestamp default current_timestamp
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            secret TEXT
        )             
        """)
        self._connection.commit()
        cursor.close()
    
    def execute(self, query, params=()):
        if not self._connection:
            raise RuntimeError("Database connection is not available.")
        
        ret = []

        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute(query, params)
                self._connection.commit()

                if query.strip().upper().startswith(('SELECT', 'PRAGMA')):
                    ret = cursor.fetchall()
            except sqlite3.Error as e:
                print(f"Database error:{e}")
                self._connection.rollback()
                raise RuntimeError(f"Failed to execute query: {query}") from e
            finally:
                cursor.close()
        
        return ret
    
    def close(self):
        if not self._connection:
            return

        with self._lock:
            self._connection.close()
            self._connection = None









