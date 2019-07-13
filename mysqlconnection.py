import pymysql.cursors

class MySQLConnection:
    def __init__(self, db):
        connection = pymysql.connect(host = 'localhost',
                                    user = 'root',
                                    password = 'root', 
                                    db = db,
                                    charset = 'utf8mb4',
                                    cursorclass = pymysql.cursors.DictCursor,
                                    autocommit = True)
        self.connection = connection
    def query_db(self, query, data=None):
        cursor = self.connection.cursor()
        try:
            query = cursor.mogrify(query, data)
            print("Running Query:\n", query)
            cursor.execute(query, data)
            if query.lower().find("select") >= 0:
                result = cursor.fetchall()
                print("Query result:", result)
                return result
            else:
                self.connection.commit()
                if query.lower().find('insert') >= 0:
                    return cursor.lastrowid
        except Exception as e:
            print("ERROR:", e)
            return False
def __del__(self):
    self.connection.close() 


def connectToMySQL(db):
    return MySQLConnection(db)
