class Service:

    def determine_probable_name(self, s):
        if "spotify" in s:
            return "Spotify"
        if ".ipp" in s:
            return "Printer"
        return ""

    def __init__(self, s):
        self.probable_name = self.determine_probable_name(s)
        self.name = s
        self.count = 1 


    def update(self):
        self.count = self.count + 1

    def __str__(self):
        if self.probable_name != "":
            return "Probable name: {}\nName: {}\nCount: {}\n".format(self.probable_name, self.name, self.count)
        return "Name: {}\nCount: {}\n".format(self.probable_name, self.name, self.count)

    def __repr__(self):
        return self.__str__()
