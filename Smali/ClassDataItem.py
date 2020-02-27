class ClassDataItem:
    def __init__(self, sf, insf, dm, vm):
        self.staticFields = sf
        self.instanceFields = insf
        self.directMethods = dm
        self.virtualMethods = vm
        return