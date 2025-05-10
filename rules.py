import pandas

class read_rules:
    def __init__(self):
        self.all_TCP_rules = []
        self.all_UDP_rules = []
        self.all_ICMP_rules = []

        try:
            rules = pandas.read_csv("rules.csv")
        except FileNotFoundError:
            print("\nThere are no rules file.\n")
        else: # If rules file readed successfully. 
            for written_rule in range(len(rules)):
                if rules.iloc[written_rule][1].upper() == 'TCP':
                    new_rule = TCP_rule(rules.iloc[written_rule])
                    self.all_TCP_rules.append(new_rule)
                elif rules.iloc[written_rule][1].upper() == 'UDP':
                    new_rule = UDP_rule(rules.iloc[written_rule])
                    self.all_UDP_rules.append(new_rule)
                else:
                    new_rule = ICMP_rule(rules.iloc[written_rule])
                    self.all_ICMP_rules.append(new_rule)



class TCP_rule:
    def __init__(self,rule:pandas.core.series.Series):
        self.rule_category = rule[0].lower()
        self.protocol = rule[1].upper().replace(' ','')
        self.source_IP = rule[2].replace(' ','')
        self.source_port = rule[3]
        self.destnation_IP = rule[4].replace(' ','')
        self.destnation_port = rule[5]
        self.message = rule[6]

class UDP_rule:
    def __init__(self,rule:pandas.core.series.Series):
        self.rule_category = rule[0].lower()
        self.protocol = rule[1].upper().replace(' ','')
        self.source_IP = rule[2].replace(' ','')
        self.source_port = rule[3]
        self.destnation_IP = rule[4].replace(' ','')
        self.destnation_port = rule[5]
        self.message = rule[6]

class ICMP_rule:
    def __init__(self,rule:pandas.core.series.Series):
        self.rule_category = rule[0].lower()
        self.protocol = rule[1].upper().replace(' ','')
        self.source_IP = rule[2].replace(' ','')
        self.source_port = rule[3]
        self.destnation_IP = rule[4].replace(' ','')
        self.destnation_port = rule[5]
        self.message = rule[6]

