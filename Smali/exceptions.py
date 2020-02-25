class InvalidArguments(Exception):
	def __init__(self, opcode, arguments, message):
		self.opcode = opcode
		self.arguments = arguments
		self.message = message
		return

	def toString(self):
		argumentsString = ''.join(str(arg) for arg in self.arguments)
		return "InvalidArguments\n  Opcode: " + self.opcode + "\n  Arguments: " + argumentsString + "\n  " + self.message + "."
