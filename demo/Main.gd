extends Node

enum AuthType{
	NATIVE_PLAIN = 1,
	NATIVE_HASHED,
	ED25519_PLAIN,
	ED25519_HASHED,
}

# See the create_db.sql file to insall the data needed for this test
# Run the insert record functions once, then comment it out.

var ed: Dictionary = {
	"db_plain_text_pwd": "secret",
	"db_sha1_hashed_pwd": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4",
	"db_sha1_hashed_pwd_b64": "5en6G6MezRroT3XKqkdPOmY/BfQ=",
	"db_sha512_hashed_pwd": 
		"bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d68" +
		"2ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2",
	"db_sha512_hashed_pwd_b64": 
		"vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==",
	"db_hostname": "127.0.0.1",
	"db_max_conns": 5,
	"db_name": "Godot_Test",
	"db_port": 3306,
	"db_native_user": "native_user",
	"db_ed_user": "ed_user"
}

var qry_stmt_array: PackedStringArray = [
	"SELECT * FROM Godot_Test.many_records LIMIT 1;",
	"SELECT * FROM Godot_Test.many_columns;"
]

var db: MariaDBConnector

var _auth_type: AuthType = AuthType.ED25519_HASHED


func _ready() -> void:
	
	db = MariaDBConnector.new()
	_connect_to_db_srvr(_auth_type)
	# Use inserts once to build data if using structure only
	# The release zip has the full db
#	_insert_many_columns() 
#	_insert_many_records()
	#_do_com_query(0)
	
	
	#var hasher := Argon2Hasher.new()
	#var salt: String = hasher.generate_b64_salt()
	#var hashed: String = hasher.hash_password_with_salt("secret", salt)
	#print("argon2 hash: %s" % hashed)
	
	#context_connection()
	#instantiated_connection()
	#test_prepared_select()
	#test_prepared_cmd()
	test_varbinary()
	


func _exit_tree() -> void:
	if db != null:
		db.disconnect_db()

func test_doc_paste() -> void:
	pass

func test_prepared_select() -> void:
	var ctx := MariaDBConnectContext.new()
	# Using defaults for unlisted member variables.
	ctx.db_name = ed["db_name"] as String
	ctx.username = ed["db_ed_user"] as String
	ctx.password = ed["db_sha512_hashed_pwd_b64"] as String
	
	var ctx_db := MariaDBConnector.connection_instance(ctx)
	if ctx_db == null:
		# Error is already printed by the addon
		return
	
	var stmt: String
	var d_res: Dictionary 
	stmt = "SELECT * FROM Godot_Test.diff_col WHERE uint = ? LIMIT 1;"
	d_res = ctx_db.prep_stmt(stmt)
	if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
		print(d_res)
		var prepped_params: Array[Dictionary] = [{MariaDBConnector.FieldType.FT_INT_U: 1}];
		var rows: Array[Dictionary] = ctx_db.prep_stmt_exec_select(d_res["statement_id"], prepped_params)
		if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
			print(rows)
		else:
			printerr("Error %d on exe_prep_select id:%d" % [ctx_db.last_error, int(d_res["statement_id"])])
			
	else:
		printerr("Error %d on preppared ststement %s!" % [ctx_db.last_error, stmt])
	print()


func test_prepared_cmd() -> void:
	var ctx := MariaDBConnectContext.new()
	# Using defaults for unlisted member variables.
	ctx.db_name = ed["db_name"] as String
	ctx.username = ed["db_ed_user"] as String
	ctx.password = ed["db_sha512_hashed_pwd_b64"] as String
	
	var ctx_db := MariaDBConnector.connection_instance(ctx)
	if ctx_db == null:
		# Error is already printed by the addon
		return
	#var stmt: String
	#var d_res: Dictionary 
	var stmt: String = "UPDATE Godot_Test.diff_col SET `varchar` = ? WHERE `utiny` = ?;"
	var d_res: Dictionary  = ctx_db.prep_stmt(stmt)
	if ctx_db.last_error == MariaDBConnector.OK:
		print(d_res)
		var prepped_params: Array[Dictionary] = [
			{MariaDBConnector.FT_VARCHAR: "changed"},
			{MariaDBConnector.FT_TINYINT_U: 3},
			];
		var status: Dictionary = ctx_db.prep_stmt_exec_cmd(d_res["statement_id"], prepped_params)
		if ctx_db.last_error == MariaDBConnector.OK:
			print(status)
		else:
			printerr("Error %d on exe_prep_select id:%d" % [ctx_db.last_error, int(d_res["statement_id"])])
			
	else:
		printerr("Error %d on preppared ststement %s!" % [ctx_db.last_error, stmt])
	
	print()
	
	stmt = "SELECT `varchar`, uint FROM Godot_Test.diff_col WHERE utiny = ?;"
	d_res = ctx_db.prep_stmt(stmt)
	if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
		print(d_res)
		var prepped_params: Array[Dictionary] = [{MariaDBConnector.FT_TINYINT_U: 3}];
		var rows: Array[Dictionary] = ctx_db.prep_stmt_exec_select(d_res["statement_id"], prepped_params)
		if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
			print(rows)
		else:
			printerr("Error %d on exe_prep_select id:%d" % [ctx_db.last_error, int(d_res["statement_id"])])
			
	else:
		printerr("Error %d on preppared ststement %s!" % [ctx_db.last_error, stmt])
	
	
	print()


func test_varbinary() -> void:
	var ctx := MariaDBConnectContext.new()
	ctx.hostname = ed["db_hostname"] as String
	ctx.port = ed["db_port"]
	ctx.db_name = ed["db_name"] as String
	ctx.username = ed["db_ed_user"] as String
	ctx.password = ed["db_sha512_hashed_pwd_b64"] as String
	# You can now store passwords as base64
	ctx.encoding = MariaDBConnectContext.ENCODE_BASE64 # Default, for exmaple only
	#ctx.password = ed["db_sha512_hashed_pwd"] as String
	#ctx.encoding = MariaDBConnectionContext.ENCODE_HEX
	ctx.auth_type = MariaDBConnectContext.AUTH_TYPE_ED25519 # Default, for exmaple only
	var ctx_db := MariaDBConnector.new()
	var err: MariaDBConnector.ErrorCode = ctx_db.connect_db_ctx(ctx)
	if err != MariaDBConnector.ErrorCode.OK:
		push_error(err)
		return
	
	var stmt: String = "SELECT * FROM `varbinary`;" 
	var rows: Array[Dictionary] = ctx_db.select_query(stmt)
	if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
		print("rows:", rows)
	else:
		printerr("Error %d on select" % [ctx_db.last_error])


func context_connection() -> void:
	var ctx := MariaDBConnectContext.new()
	ctx.hostname = ed["db_hostname"] as String
	ctx.port = ed["db_port"]
	ctx.db_name = ed["db_name"] as String
	ctx.username = ed["db_ed_user"] as String
	ctx.password = ed["db_sha512_hashed_pwd_b64"] as String
	# You can now store passwords as base64
	ctx.encoding = MariaDBConnectContext.ENCODE_BASE64 # Default, for exmaple only
	#ctx.password = ed["db_sha512_hashed_pwd"] as String
	#ctx.encoding = MariaDBConnectionContext.ENCODE_HEX
	ctx.auth_type = MariaDBConnectContext.AUTH_TYPE_ED25519 # Default, for exmaple only
	
	var ctx_db := MariaDBConnector.new()
	var err: MariaDBConnector.ErrorCode = ctx_db.connect_db_ctx(ctx)
	if err != MariaDBConnector.ErrorCode.OK:
		push_error(err)
		return
	
	var stmt: String = "INSERT INTO Godot_Test.many_records (type, zone_id, player_id, map_id, " +\
			"text_field) VALUES " 
	
	var type: int = randi() % 100
	var zone: int = randi() % 100
	var plyr_id: int = randi() % 65536
	var map_id: int = randi() % 24
	var txt: String = "Some text for record player %d" % plyr_id
	
	stmt += "(%d, %d, %d, %d, '%s');" % [type, zone, plyr_id, map_id, txt]
	var res: Dictionary = ctx_db.execute_command(stmt)
	if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
		print("rows affected:", res)
	else:
		printerr("Error %d on INSERT" % [ctx_db.last_error])
	
	stmt = "SELECT * FROM Godot_Test.many_records WHERE " + \
		"type = %d AND zone_id = %d AND player_id = %d AND map_id = %d LIMIT 1;" % [
		type, zone, plyr_id, map_id]
	var rows: Array[Dictionary] = ctx_db.select_query(stmt)
	if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
		print("rows:", rows)
	else:
		printerr("Error %d on select" % [ctx_db.last_error])


func instantiated_connection() -> void:
	var ctx := MariaDBConnectContext.new()
	ctx.db_name = ed["db_name"] as String
	ctx.username = ed["db_ed_user"] as String
	ctx.password = ed["db_sha512_hashed_pwd_b64"] as String
	
	var ctx_db := MariaDBConnector.connection_instance(ctx)
	if ctx_db == null:
		# Error is already printed by the addon
		return
	
	var stmt: String = "SELECT id, type, zone_id, player_id, map_id FROM " + \
		"Godot_Test.many_records LIMIT 5;"
	var rows: Array[Dictionary] = ctx_db.select_query(stmt)
	if ctx_db.last_error == MariaDBConnector.ErrorCode.OK:
		for row:Dictionary in rows:
			print("row:", row)
	else:
		printerr("Error %d on select" % [ctx_db.last_error])
	


func print_db_response(pba: PackedByteArray) -> void:
	for idx in range(pba.size() - 1, -1, -1):
		if pba[idx] < 32:
			pba.remove_at(idx)
	print(pba.get_string_from_ascii())


func _do_com_query(p_query_stmt_idx: int) -> void:
	if db.is_connected_db():
		var start_uticks := Time.get_ticks_usec()
		var stmt: String = qry_stmt_array[p_query_stmt_idx]
		print(stmt)
		var qry = db.query(stmt)
		if typeof(qry) == TYPE_ARRAY:
			print("total records received:", qry.size(), " time:", 
				Time.get_ticks_usec() - start_uticks)
			if qry.size() > 0:
				print(qry[0])
		else:
			print(stmt)
			print("ERROR:", qry)
	else:
		push_error("DB not connected")


func _connect_to_db_srvr(p_auth_type: AuthType) -> void:
	var err: int = MariaDBConnector.ErrorCode.OK
	match p_auth_type:
		AuthType.NATIVE_PLAIN:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_native_user"],
					ed["db_plain_text_pwd"],
					MariaDBConnector.AUTH_TYPE_MYSQL_NATIVE,
					false
			)
		AuthType.NATIVE_HASHED:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_native_user"],
					ed["db_sha1_hashed_pwd"],
					MariaDBConnector.AUTH_TYPE_MYSQL_NATIVE
			)
		AuthType.ED25519_PLAIN:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_ed_user"],
					ed["db_plain_text_pwd"],
					MariaDBConnector.AUTH_TYPE_ED25519,
					false
			)
		AuthType.ED25519_HASHED:
				err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_ed_user"],
					ed["db_sha512_hashed_pwd"],
					MariaDBConnector.AUTH_TYPE_ED25519
			)
	if err:
		print("db connect err:", err)


func _insert_many_columns() -> void:
	var stmt: String = "INSERT INTO Godot_Test.many_columns VALUES "
	for i in range(1, 253):
		stmt += "(%d)" % i
	
	stmt += ";"
	print(stmt)
	var err = db.query(stmt)
	if err != OK:
		printerr("Insert fail:" , err)


func _insert_many_records() -> void:
	var stmt: String = "INSERT INTO Godot_Test.many_records (type, zone_id, player_id, map_id, " +\
			"text_field) VALUES " 
	for i in 10:
		stmt += "(%d, %d, %d, %d, '%s')" % [i * 10 + 1, i * 10 + 2, i * 10 + 3, i * 10 + 4, 
			"Some text for record %d" % i]
	
	stmt += ";"
	print(stmt)
	var err = db.query(stmt)
	if err != OK:
		printerr("Insert fail:" , err)
