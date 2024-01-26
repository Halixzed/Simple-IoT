class TempController:

    def __init__(self):
        self.isTurnedOn = "OFF"
        self.temperatureDegrees = 0 

    def set_state(self, isTurnedOn):
        self.isTurnedOn = isTurnedOn

    def set_temp(self, temperatureDegrees):
        self.temperatureDegrees = temperatureDegrees

    def get_current(self):
        return f"Current State: {self.isTurnedOn}, Current Temperature: {self.temperatureDegrees}"