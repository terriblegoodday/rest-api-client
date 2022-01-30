import pycurl, json, base64, io

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class User:
	username: str
	password: str
	
	def __init__(self, username, password):
		self.username = username
		self.password = password
		
	def decode(json):
		user = User(json["username"], json["password"])
		
		return user
		
def verify_user(user: User) -> bool:
	c = pycurl.Curl()
	c.setopt(pycurl.CUSTOMREQUEST, "POST")
	c.setopt(pycurl.URL, "127.0.0.1:8080/login")
	c.setopt(pycurl.FOLLOWLOCATION, 1)
	c.setopt(pycurl.DEFAULT_PROTOCOL, "http")
	
	auth = user.username + ":" + user.password
	auth_bytes = auth.encode('utf8')
	base64_bytes = base64.b64encode(auth_bytes)
	base64_message = base64_bytes.decode('utf8')
	
	buffer = io.BytesIO()
	
	c.setopt(pycurl.HTTPHEADER, ["Authorization: Basic " + base64_message])
	c.setopt(c.WRITEFUNCTION, buffer.write)
	c.perform()
	c.close()
	
	response = buffer.getvalue()
	
	json_response = json.loads(response)
		
	return json_response.get("passwordHash") != None
	
def get_todos():
	print(bcolors.OKGREEN + bcolors.BOLD + "Getting your todos..." + bcolors.ENDC + bcolors.ENDC)

	c = pycurl.Curl()
	c.setopt(pycurl.CUSTOMREQUEST, "GET")
	c.setopt(pycurl.URL, "127.0.0.1:8080/todo")
	c.setopt(pycurl.FOLLOWLOCATION, 1)
	c.setopt(pycurl.DEFAULT_PROTOCOL, "http")
	
	auth = user.username + ":" + user.password
	auth_bytes = auth.encode('utf8')
	base64_bytes = base64.b64encode(auth_bytes)
	base64_message = base64_bytes.decode('utf8')
	
	buffer = io.BytesIO()
	
	c.setopt(pycurl.HTTPHEADER, ["Authorization: Basic " + base64_message])
	c.setopt(c.WRITEFUNCTION, buffer.write)
	c.perform()
	c.close()
	
	response = buffer.getvalue()
	
	json_response = json.loads(response)
	
	for todo in json_response:
		print(bcolors.OKBLUE + bcolors.BOLD + todo.get("title") + " " + bcolors.ENDC + bcolors.ENDC + ("[x]" if todo.get("completed") else "[ ]"))
		
def new_todo():
	input_todo = input(bcolors.OKGREEN + bcolors.BOLD + "Input your todo name:" + bcolors.ENDC + bcolors.ENDC + " ")
	input_dict = {
		"title": input_todo
	}
	todo_json = json.dumps(input_dict)
	
	c = pycurl.Curl()
	c.setopt(pycurl.CUSTOMREQUEST, "POST")
	c.setopt(pycurl.URL, "127.0.0.1:8080/todo")
	c.setopt(pycurl.FOLLOWLOCATION, 1)
	c.setopt(pycurl.DEFAULT_PROTOCOL, "http")
	
	auth = user.username + ":" + user.password
	auth_bytes = auth.encode('utf8')
	base64_bytes = base64.b64encode(auth_bytes)
	base64_message = base64_bytes.decode('utf8')
	
	buffer = io.BytesIO()
	
	c.setopt(pycurl.HTTPHEADER, ["Authorization: Basic " + base64_message, "Content-Type: application/json"])
	c.setopt(c.WRITEFUNCTION, buffer.write)
	c.setopt(pycurl.POSTFIELDS, todo_json)
	c.perform()
	c.close()

def upload_file():
	input_filename = input(bcolors.OKGREEN + bcolors.BOLD + "Input your file name:" + bcolors.ENDC + bcolors.ENDC + " ")

	file = str(open(input_filename, "r").buffer)

	c = pycurl.Curl()
	c.setopt(pycurl.CUSTOMREQUEST, "POST")
	c.setopt(pycurl.URL, "127.0.0.1:8080/files/" + input_filename)
	c.setopt(pycurl.FOLLOWLOCATION, 1)
	c.setopt(pycurl.POSTFIELDS, file)
	
	c.perform()
	c.close()

def get_file():
	input_filename = input(bcolors.OKGREEN + bcolors.BOLD + "Input your file name:" + bcolors.ENDC + bcolors.ENDC + " ")

	with open(input_filename, "wb") as file:
		c = pycurl.Curl()
		c.setopt(pycurl.CUSTOMREQUEST, "GET")
		c.setopt(pycurl.URL, "127.0.0.1:8080/files/" + input_filename)
		c.setopt(pycurl.FOLLOWLOCATION, 1)
		c.setopt(pycurl.WRITEDATA, file)
		
		c.perform()
		c.close()

def get_files():
	c = pycurl.Curl()
	c.setopt(pycurl.CUSTOMREQUEST, "GET")
	c.setopt(pycurl.URL, "127.0.0.1:8080/files")
	c.setopt(pycurl.FOLLOWLOCATION, 1)

	buffer = io.BytesIO()
	
	c.setopt(c.WRITEFUNCTION, buffer.write)
	c.perform()
	c.close()
	
	response = buffer.getvalue()
	
	json_response = json.loads(response)
	
	for file in json_response:
		print(bcolors.OKBLUE + bcolors.BOLD + file.get("name") + " " + bcolors.ENDC + bcolors.ENDC + str(file["size"]))

def remove_file():
	input_filename = input(bcolors.OKGREEN + bcolors.BOLD + "Input your file name:" + bcolors.ENDC + bcolors.ENDC + " ")

	c = pycurl.Curl()
	c.setopt(pycurl.CUSTOMREQUEST, "DELETE")
	c.setopt(pycurl.URL, "127.0.0.1:8080/files/" + input_filename)
	c.setopt(pycurl.FOLLOWLOCATION, 1)
	
	c.perform()
	c.close()

	
def main_menu():
	print("Choose your endpoint:")
	print(bcolors.OKBLUE + bcolors.BOLD + "[1] " + bcolors.ENDC + bcolors.ENDC + "Get todos")
	print(bcolors.OKBLUE + bcolors.BOLD + "[2] " + bcolors.ENDC + bcolors.ENDC + "New todo")
	print(bcolors.OKBLUE + bcolors.BOLD + "[3] " + bcolors.ENDC + bcolors.ENDC + "Upload file")
	print(bcolors.OKBLUE + bcolors.BOLD + "[4] " + bcolors.ENDC + bcolors.ENDC + "Download file")
	print(bcolors.OKBLUE + bcolors.BOLD + "[5] " + bcolors.ENDC + bcolors.ENDC + "Index files")
	print(bcolors.OKBLUE + bcolors.BOLD + "[6] " + bcolors.ENDC + bcolors.ENDC + "Remove file")
	print(bcolors.WARNING + bcolors.BOLD + "[7] " + bcolors.ENDC + bcolors.ENDC + "Exit")
	
	input_number = input("Input number: ")
	
	if input_number == "1":
		get_todos()
	if input_number == "2":
		new_todo()
	if input_number == "3":
		upload_file()
	if input_number == "4":
		get_file()
	if input_number == "5":
		get_files()
	if input_number == "6":
		remove_file()
	
	return input_number == "7"
	
is_authenticated = False
user = None

while not is_authenticated:
	line = None
	
	try:
		input_file = open("authentication.txt", "r")
		line = input_file.read()
		input_file.close()
	except:
		print("No auth file available")

	if line:
		user_json = json.loads(line)
		user = User.decode(user_json)
	else:
		username = input(bcolors.WARNING + bcolors.UNDERLINE + "Enter username:" + bcolors.ENDC + bcolors.ENDC + " ")
		password = input(bcolors.WARNING + bcolors.UNDERLINE + "Enter password:" + bcolors.ENDC + bcolors.ENDC + " ")
	
		user = User(username, password)
	
	

	output_file = open("authentication.txt", "w")
	
	is_authenticated = verify_user(user)
	if is_authenticated:
		encoded_user = json.dumps(user, default=vars)
	
		output_file.write(encoded_user)
	else:
		output_file.truncate(0)
		print("Incorrect username or password")

	output_file.close()  
	
	
print("Authenticated as: " + bcolors.OKGREEN + bcolors.BOLD + user.username + bcolors.ENDC + bcolors.ENDC)

should_close = False

while not should_close:
	should_close = main_menu()
	