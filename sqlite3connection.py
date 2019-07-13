import sqlite3

def make_dict(arr1, arr2):
    result = []
    if len(arr1) < 1:
        return result
    if len(arr1[0]) != len(arr2):
        raise Exception('columns and data do not match')
    for row in arr1:
        row_dict = dict()
        for j in range(len(row)):
            row_dict[arr2[j][0]] = row[j]
        result.append(row_dict)
    return result

class SQLite3Connection:
    def __init__(self, db):
        connection = sqlite3.connect(db)
        connection.set_trace_callback(print)
        self.connection = connection
    def query_db(self, query, data=[]):
        cursor = self.connection.cursor()
        try:
            print("Running query:")
            cursor.execute(query, data)
            if query.lower().find("select") >= 0:
                res = cursor.fetchall()
                columns = cursor.description
                result = make_dict(res, columns)
                print("Query result:", result)
                return result
            else:
                self.connection.commit()
                if query.lower().find("insert") >= 0:
                    return cursor.lastrowid
        except Exception as e:
            print("ERROR:", e)
            return False
    def __del__(self):
        self.connection.close()

def connectToSQLite3(db):
    return SQLite3Connection(db)
