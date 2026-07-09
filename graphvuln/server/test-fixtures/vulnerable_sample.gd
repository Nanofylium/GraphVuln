extends Node

var api_key = "sk_live_abcdef1234567890"

func _ready():
	var token = str(randi())
	print("user password is: " + password)

func do_query(user_input):
	var query = "SELECT * FROM users WHERE name = '" + user_input + "'"
	db.query(query)

func load_file(user_path):
	var f = FileAccess.open("res://data/" + user_path, FileAccess.READ)

func run_cmd(user_cmd):
	OS.execute("sh -c " + user_cmd)

func hash_password(pw):
	return md5(pw)

@rpc("any_peer")
func give_admin(peer_id):
	users[peer_id].role = "admin"

func check_token(input_token):
	if input_token == secret_token:
		return true

func send_error(response):
	response.send_text("error: " + str(get_stack()))

func do_redirect(user_target):
	var location = "https://mysite.com/" + user_target
