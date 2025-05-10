class SYN_Flood_Detection:

    def __init__(self,maximum_syn):
        self.ack_packets_counter = 0
        self.maximum_syn = maximum_syn

    def ack_packet_recived(self):
        self.ack_packets_counter += 1
    def ack_flood_attack_detected(self):
        if self.ack_packets_counter > self.maximum_syn:
            return True
    def reset_counter(self):
        self.ack_packets_counter = 0
