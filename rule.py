''' 

Ariana I. Rios Montaner
Class that represents each firewall rule that is iterated. 

'''

class Rule:
    def __init__(self, RuleId, FromPort, IpRanges, ToPort, Action, Direction):
        self.set_RuleId(RuleId)
        self.set_FromPort(FromPort)
        self.set_IpRanges(IpRanges)
        self.set_ToPort(ToPort)
        self.set_Action(Action)
        self.set_Direction(Direction)

    # Getter and Setter for RuleId (string)
    def get_RuleId(self):
        return self._RuleId

    def set_RuleId(self, RuleId):
        if isinstance(RuleId, str):
            self._RuleId = RuleId
        else:
            raise TypeError("RuleId must be a string")

    # Getter and Setter for FromPort (integer)
    def get_FromPort(self):
        return self._FromPort

    def set_FromPort(self, FromPort):
        if isinstance(FromPort, int):
            self._FromPort = FromPort
        else:
            raise TypeError("FromPort must be an integer")

    # Getter and Setter for IpRanges (list of strings)
    def get_IpRanges(self):
        return self._IpRanges

    def set_IpRanges(self, IpRanges):
        if isinstance(IpRanges, list) and all(isinstance(ip, str) for ip in IpRanges):
            self._IpRanges = IpRanges
        else:
            raise TypeError("IpRanges must be a list of strings")

    # Getter and Setter for ToPort (integer)
    def get_ToPort(self):
        return self._ToPort

    def set_ToPort(self, ToPort):
        if isinstance(ToPort, int):
            self._ToPort = ToPort
        else:
            raise TypeError("ToPort must be an integer")

    # Getter and Setter for Action (string, must be "Allow" or "Deny")
    def get_Action(self):
        return self._Action

    def set_Action(self, Action):
        if isinstance(Action, str) and Action in ["Allow", "Deny"]:
            self._Action = Action
        else:
            raise ValueError('Action must be either "Allow" or "Deny"')

    # Getter and Setter for Direction (string, must be "Ingress" or "Egress")
    def get_Direction(self):
        return self._Direction

    def set_Direction(self, Direction):
        if isinstance(Direction, str) and Direction in ["Ingress", "Egress"]:
            self._Direction = Direction
        else:
            raise ValueError('Direction must be either "Ingress or "Egress"')

    # __repr__ method to represent the object as a string
    def __repr__(self):
        return (f"Rule(RuleId={self._RuleId}, FromPort={self._FromPort}, "
                f"IpRanges={self._IpRanges}, ToPort={self._ToPort}, "
                f"Action={self._Action}, Direction={self._Direction})")
