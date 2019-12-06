import json


class Policy:
    """
    A helper class for modifying a policy in the AWS IAM Format
    """

    @classmethod
    def from_string(cls, policy):
        return cls.__init__(json.loads(policy))

    def __init__(self, policy: dict = None):
        """

        :param policy:
        """
        self.policy = policy if policy else {
            "Version": "2012-10-17",
            "Statement": []}
        self.statements = dict([Statement(statement) for statement in self.policy['Statement']])

    def new_statement(self, sid: str):
        if sid not in self.statements:
            self.statements[sid] = Statement.from_sid(sid)
            return self.statements[sid]

    def add_statement(self, statement: dict, replace=False):
        statement = Statement(statement)
        if statement.sid in self.statements:
            if replace:
                self.statements[statement.sid] = statement
            else:
                raise ValueError(f"The Statement '{statement.sid}' already exists in '{self.__class__.__name__}'")
        else:
            self.statements[statement.sid] = statement
        return statement

    def remove_statement(self, sid):
        if len(self.statements) > 1:
            self.statements.pop(sid)
        else:
            ValueError(f"The statements cannot be empty.")

    def get_statement(self, sid):
        return self.statements[sid]

    def __str__(self):
        self.policy['Statement'] = [s.value for s in self.statements.values()]
        return json.dumps(self.policy)


class Statement:
    """A helper class for managing policy statements"""

    @classmethod
    def from_sid(cls, sid):
        """
        Creates a statement skeleton with the Sid set.
        :param sid: the name of the statement
        :return:
        """
        return cls({
            "Sid": sid,
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
            ],
            "Resource": [],
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "fus:entities": []
                }
            }
        })

    def __init__(self, statement: dict):
        """

        :param statement:
        """
        if not statement.get('Sid'):
            raise ValueError("Statement must have Sid.")
        self.value = statement

    @property
    def sid(self):
        return self.value['Sid']

    @staticmethod
    def _add(item_list: list, addition: str):
        if addition in item_list:
            return
        else:
            item_list.append(addition)

    def add_action(self, action: str):
        self._add(self.value['action'], action)

    def add_entity(self, entity: str):
        self._add(self.value['Condition']['ForAnyValue:StringEquals']['fus:entities'], entity)

    def add_resource(self, resource: str):
        self._add(self.value['Resource'], resource)

    @staticmethod
    def _remove(item_list: list, subtraction: str):
        if subtraction in item_list and len(item_list) > 1:
            item_list.remove(subtraction)
        raise ValueError(f"The List cannot be empty.")

    def remove_action(self, action: str):
        self._remove(self.value['action'], action)

    def remove_entity(self, entity):
        self._remove(self.value['Condition']['ForAnyValue:StringEquals']['fus:entities'], entity)

    def remove_resource(self, resource):
        self._remove(self.value['Resource'], resource)
