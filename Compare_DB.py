import os, sys
import re
import winrm
import logging

class SQL_Verify(object):

    def __init__(self, SQL_Host_IP, auth):
        """# Pre-requisite for SQL setup
        Run following commands on your SQL machine to enable WinRM
        winrm qc -q
        winrm set winrm/config/client/auth @{Basic="true"}
        winrm set winrm/config/service/auth @{Basic="true"}
        winrm set winrm/config/service @{AllowUnencrypted="true"}
        """
        # Create log file
        logging.basicConfig(filename='Log_File.log', level=logging.DEBUG)
        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)
        # Append to path, in case not present
        sys.path.append(r"C:\Program Files\Microsoft SQL Server\110\Tools\Binn")
        # Create session with SQL host
        self.SQL_Host_IP = SQL_Host_IP
        self.auth = auth
        self.session = winrm.Session(self.SQL_Host_IP, self.auth)

        # Directory for storing the data files.
        if not os.path.exists("C:\SQL_Data"):
            os.mkdir("C:\SQL_Data")
        else:
            os.system("RMDIR /S /Q C:\SQL_Data")
            os.system("MKDIR C:\SQL_Data")

    def get_table_list_in_DB(self, Instance_name, DB_name):
        '''
        Returns the list of table in the given database
        '''
        output_file = "C:\\SQL_Data\\Table_list_DB-%s_Output.txt" %(DB_name)

        query = 'SELECT NAME from [%s].sys.tables' %(DB_name)
        command = 'sqlcmd -S "%s" -Q "%s"' %(Instance_name, query)

        output = self._execute_remote_ps_command(command)
        if not output:
            self.log(
                "Error in command execution :- get_table_list_in_DB :- [%s, %s] "
                %(Instance_name, DB_name))
            return False
        with open(output_file, 'w') as f:
            f.write(output)
        return output_file

    def get_table_list_in_DB(self, Instance_name, DB_name):
        '''
        Returns the list of table in the given database.

        Arguments :-
        Instance_name :- Name of the instance on which the db is present
        DB_name  :- name of DB, whose table list needs to be fetched
        '''
        output_file = "C:\\SQL_Data\\Table_list_DB-%s_Output.txt" %(DB_name)

        query = 'SELECT NAME from [%s].sys.tables' %(DB_name)
        command = 'sqlcmd -S "%s" -Q "%s"' %(Instance_name, query)

        output = self._execute_remote_ps_command(command)
        if not output:
            self.log(
                "Error in command execution :- get_table_list_in_DB :- [%s, %s] "
                %(Instance_name, DB_name))
            return False
        with open(output_file, 'w') as f:
            f.write(output)
        return output_file

    def get_db_Schema(self, Instance_name, DB_name):
        '''
        From the given DB, it fetches the schema of all existing
        tables and append those in a single dictionary with
        key as table name and returns the dictionary

        Arguments :-
        Instance_name :- Name of the instance on which the db is present
        DB_name  :- name of DB, whose schema needs to be fetched
        '''
        table_list = self.get_table_list_in_DB(Instance_name, DB_name)
        flag = 0
        db_schema = {}
        with open(table_list, 'r') as f1:
            for lines in f1:
                if re.match("^\s", lines):
                    flag = 0
                if flag:
                    table_name=lines.strip()
                    table_schema = self.get_table_Schema(
                        Instance_name,
                        DB_name, table_name)
                    db_schema.update(table_schema)
                if re.match("^----+?-", lines):
                    flag = 1
        return db_schema

    def get_table_Schema(self, Instance_name, DB_name, table_name):
        '''
        Queries and returns the table schema

        Arguments :-
        Instance_name :- Name of the instance on which the db is present
        DB_name  :- name of DB, where the table being queried is present
        table_name :- name of the table whose schema is to be queried
        '''
        table_schema = {}
        query = """
        SELECT ORDINAL_POSITION, COLUMN_NAME, DATA_TYPE,
        CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE
        FROM [%s].INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = '%s'""".replace('\n', '') %(DB_name, table_name)

        command = 'sqlcmd -S "%s" -Q "%s"' %(Instance_name, query)
        output = self._execute_remote_ps_command(command)
        if not output:
            self.log(
                "Error in command execution :- get_table_Schema :- [%s, %s, %s] "
                %(Instance_name, DB_name, table_name))
            return False
        table_schema[table_name] = output
        return table_schema

    def get_db_data(self, Instance_name, DB_name):
        '''
        From the given DB, it fetches the data of all existing
        tables and append those in a single dictionary with
        key as table name and returns the dictionary

        Arguments :-
        Instance_name :- Name of the instance on which the db is present
        DB_name  :- name of DB, whose table data needs to be fetched
        '''
        db_data = {}
        table_list = self.get_table_list_in_DB(Instance_name, DB_name)
        flag = 0
        with open(table_list, 'r') as f1:
            for lines in f1:
                if re.match("^\s", lines):
                    flag = 0
                if flag:
                    table_name=lines.strip()
                    table_data = self.get_table_data(
                        Instance_name,
                        DB_name, table_name)
                    db_data.update(table_data)
                if re.match("^----+?-", lines):
                    flag = 1
        return db_data

    def get_table_data(self, Instance_name, DB_name, table_name):
        '''
        Queries and returns the data for the given table

        Arguments :-
        Instance_name :- Name of the instance on which the db is present
        DB_name  :- name of DB, where the table being queired resides
        table_name :- name of the table whose data is to be queried
        '''
        table_data = {}
        query = "SELECT * from [%s].dbo.[%s]" %(DB_name, table_name)
        command = 'sqlcmd -S "%s" -Q "%s"' %(Instance_name, query)
        output = self._execute_remote_ps_command(command)
        if not output:
            self.log(
                "Error in command execution :- get_table_data :- [%s, %s, %s] "
                %(Instance_name, DB_name, table_name))
            return False
        table_data[table_name] = output
        return table_data

    def compare_DB_Data(self, DB_Detail1=[], DB_Detail2=[]):
        '''
        Take detail of two DBs as input and gets the detailed DB data
        The data collected are dumped into one dictionary and at last
        both the dictionary are compared.

        Arguments :-
        DB_Detail1 :- a list of instance name and DB name for original DB
        DB_Detail2 :- a list of instance name and DB name for Restored DB
        e.g :- DB_Detail1 = ['Instance_name1', 'Database_name1']
        '''
        # Compare schema
        db_schema1 = self.get_db_Schema(
            Instance_name=DB_Detail1[0],
            DB_name=DB_Detail1[1])
        db_schema2 = self.get_db_Schema(
            Instance_name=DB_Detail2[0],
            DB_name=DB_Detail2[1])
        schema1_diff_schema2 = {}
        schema2_diff_schema1 = {}

        set_current, set_past = set(db_schema1.keys()), set(db_schema2.keys())
        intersect = set_current.intersection(set_past)
        added = set_current - intersect
        removed = set_past - intersect
        changed = set(k for k in intersect if db_schema2[k] != db_schema1[k])
        unchanged = set(k for k in intersect if db_schema2[k] == db_schema1[k])
        #print added,removed,changed,unchanged

        [schema1_diff_schema2.update(i)
         for i in [{m : db_schema1[m]} for m in added ]]
        [schema1_diff_schema2.update(i)
         for i in [{m : db_schema1[m]} for m in changed]]
        [schema2_diff_schema1.update(i)
         for i in [{m : db_schema2[m]} for m in removed]]
        [schema2_diff_schema1.update(i)
         for i in [{m : db_schema2[m]} for m in changed]]

        if added ==  set([]) and removed == set([]) and changed == set([]):
            self.log("Schema of both DB Matches")
        else:
            self.log("Schema of both DB Varies")
            #self.log("Diff Shcema1 vs Shcema2 :- %s" %schema1_diff_schema2)
            #self.log("Diff Shcema1 vs Shcema2 :- %s" %schema2_diff_schema1)
            self.log("Changed DB Scehma :- %s" %changed)
            self.log("Unchanged DB Schema :- %s" %unchanged)

        # Compare data
        # Data for DB1
        data_DB1 = self.get_db_data(
            Instance_name=DB_Detail1[0], DB_name=DB_Detail1[1])
        # Data for DB2
        data_DB2 = self.get_db_data(
            Instance_name=DB_Detail2[0], DB_name=DB_Detail2[1])

        data1_diff_data2 = {}
        data2_diff_data1 = {}
        set_current_data, set_past_data = set(data_DB1.keys()), set(data_DB2.keys())
        intersect = set_current_data.intersection(set_past_data)
        added = set_current_data - intersect
        removed = set_past_data - intersect
        changed = set(k for k in intersect if data_DB2[k] != data_DB1[k])
        unchanged = set(k for k in intersect if data_DB2[k] == data_DB1[k])
        #print added,removed,changed,unchanged

        [data1_diff_data2.update(i) for i in [{m : data_DB1[m]} for m in added ]]
        [data1_diff_data2.update(i) for i in [{m : data_DB1[m]} for m in changed]]
        [data2_diff_data1.update(i) for i in [{m : data_DB2[m]} for m in removed]]
        [data2_diff_data1.update(i) for i in [{m : data_DB2[m]} for m in changed]]

        if added ==  set([]) and removed == set([]) and changed == set([]):
            self.log("Data of both DB Matches")
            return True
        else:
            #self.log("Diff DB1 vs DB2 :- %s " %(data1_diff_data2))
            #self.log("Diff DB1 vs DB2 :- %s" %(data2_diff_data1))
            self.log("Changed DB Data :- %s" %changed)
            self.log("Unchanged DB Data :- %s" %unchanged)
            asserts.fail("Data of both DB Varies")
            return False

    def delete_db(self, Instance_name, DB_name):
        '''
        This method deletes the given database
        '''
        query = "DROP DATABASE [%s]" %(DB_name)
        command = 'sqlcmd -S "%s" -Q "%s"' %(Instance_name, query)
        output = self._execute_remote_ps_command(command)
        if not output:
            self.log(
                "Error in command execution :- get_table_data :- [%s, %s, %s] "
                %(Instance_name, DB_name, table_name))
            return False
        return True

    def delete_restored_db(self, Instance_name, DB_name):
        '''
        Deletes all the restored DB of given DB
        Searches 'rst_' and DB name from all existing DBs
        and deletes the matching ones
        '''
        op_before_delete = r"C:\SQL_Data\output_before_delete.txt"
        op_after_delete = r"C:\SQL_Data\output_after_delete.txt"

        query = "select NAME from sys.databases"
        command = 'sqlcmd -S "%s" -Q "%s"'%(Instance_name, query)

        output = self._execute_remote_ps_command(command)
        if not output:
            self.log(
                "Error in command execution :- get_table_data :- [%s, %s, %s] "
                %(Instance_name, DB_name, table_name))
            return False
        with open(op_before_delete, 'w') as f:
            f.write(output)   # all the db name
        db_list = []

        with open(op_before_delete, 'r') as f:
            for lines in f:
                pt = re.compile(r"" + "rst_" + ".*" + DB_name +"[_?\d]*$")
                m = re.findall(pt , lines.strip())
                if m != []:
                    db_list.append(m[0])

        print db_list
        for db in db_list:
            self.delete_db(Instance_name, db)

        output2 = self._execute_remote_ps_command(command)
        if not output2:
            self.log(
                "Error in command execution :- get_table_data :- [%s, %s, %s] "
                %(Instance_name, DB_name, table_name))
            return False
        with open(op_after_delete, 'w') as f2:
            f2.write(output2)    # all the db name after delete
        with open(op_after_delete, 'r') as f2:
            if any (db in line.strip() for line in f2 for db in db_list):
                self.log("All the restored databases were not deleted")
                [db for db in db_list for line in f2 if db in line.strip()]
            else:
                self.log.info("All the Restored dbs were deleted successfully")
                self.log.debug("Total number of DBs deleted  :- ", len(db_list))
                self.log.debug("Deleted DBs :- ", db_list)

    def _execute_remote_ps_command(self, command):
        '''
        This method executes the command on SQL host and returns the output.
        '''
        try:
            execute_query = self.session.run_ps(command)
        except Exception, e:
            self.log.warning("Exception occured :- %s" % str(e))
            try:
                self.session = winrm.Session(self.SQL_Host_IP, self.auth)
                #self.log("Retrying with new session object :- %s" % (session))
                execute_query = self.session.run_ps(command)
            except Exception, e:
                self.log.error("Exception occured :- %s" % str(e))
                self.session = winrm.Session(self.SQL_Host_IP, self.auth)
                #self.log("Retrying with new session object :- %s" % (session))
                execute_query = self.session.run_ps(command)

        if execute_query.std_err:
            self.log.error("Error in command execution :- " %(execute_query.std_err))

            return False
        self.log.debug("Command output - [%s]"%str(execute_query.std_out))
        return execute_query.std_out


# Sample calls
sql_ob = SQL_Verify('192.168.58.160', auth=('Administrator', 'password'))
sql_ob.compare_DB_Data(
    ['WIN-SQL', 'database7'],
    ['WIN-SQL', 'rst_database7'])
sql_ob.delete_restored_db('WIN-SQL', 'database7')
sql_ob.verify_db_is_deleted("WIN-SQL", "rst_database7")
