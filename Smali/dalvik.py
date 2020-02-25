from .exceptions import *

class Register(object):
	index
	value = 0
	isTainted = False

	def __init__(self, index, value = 0, taint = False):
		self.index = index
		self.value = value
		self.isTainted = taint
		return

	def __add__(self, y):
		if isinstance(y, Register):
			return self.value + y.value
		return NotImplemented

	def __lt__(self, y):
		if isinstance(y, Register):
			return self.index < y.index
		if isinstance(y, int):
			return self.index < y
		return NotImplemented

	def __gt__(self, y):
		if isinstance(y, Register):
			return self.index > y.index
		if isinstance(y, int):
			return self.index > y
		return NotImplemented

class VirtualMachine(object):
	currentState = {}
	stateStack = []

	def __init__(self):
		return

	def move(self, vx, vy):
		if(vx > 255 or vy > 255):
			raise InvalidArguments("move (0x01)", [vx, vy], "Both registers are required to be in the first 256 registers")
			return
		if(not vx in currentState):
			currentState.append(Register(vx))
		if(not vy in currentState):
			currentState.append(Register(vy))
		
		self.state[vx] = vy
		return

	def moveResult(self, vx):
		return
