/*************************************************************************/
/*  mariadb.hpp                                                          */
/*************************************************************************/
/*                     This file is part of the                          */
/*                      MariaDBConnector addon                           */
/*                    for use in the Godot Engine                        */
/*                           GODOT ENGINE                                */
/*                      https://godotengine.org                          */
/*************************************************************************/
/* Copyright (c) 2021-2025 Shawn Shipton. https://vikingtinkerer.com     */
/*                                                                       */
/* Permission is hereby granted, free of charge, to any person obtaining */
/* a copy of this software and associated documentation files (the       */
/* "Software"), to deal in the Software without restriction, including   */
/* without limitation the rights to use, copy, modify, merge, publish,   */
/* distribute, sublicense, and/or sell copies of the Software, and to    */
/* permit persons to whom the Software is furnished to do so, subject to */
/* the following conditions:                                             */
/*                                                                       */
/* The above copyright notice and this permission notice shall be        */
/* included in all copies or substantial portions of the Software.       */
/*                                                                       */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*/
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY  */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,  */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE     */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                */
/*************************************************************************/

#pragma once

#include "mariadb_connect_context.hpp"
#include "mariadb_connector_common.hpp"

#include <godot_cpp/classes/ip.hpp>
#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/classes/stream_peer_tcp.hpp>
#include <godot_cpp/core/binder_common.hpp>
#include <godot_cpp/core/class_db.hpp>

// #include <thread>
// #include <godot_cpp/classes/thread.hpp>
#include <godot_cpp/classes/mutex.hpp>

using namespace godot;

constexpr uint8_t kCharacterCollationId = 33;  //utf8_general_ci
constexpr char* kCharacterCollationName = (char*)"utf8_general_ci";

class MariaDBConnector : public RefCounted {
	GDCLASS(MariaDBConnector, RefCounted);

public:
	enum AuthType {
		AUTH_TYPE_ED25519 = MariaDBConnectorCommon::AUTH_TYPE_ED25519,
		AUTH_TYPE_MYSQL_NATIVE = MariaDBConnectorCommon::AUTH_TYPE_MYSQL_NATIVE,
		AUTH_TYPE_LAST = MariaDBConnectorCommon::AUTH_TYPE_LAST
	};

	enum IpType {
		IP_TYPE_IPV4 = IP::TYPE_IPV4,
		IP_TYPE_IPV6 = IP::TYPE_IPV6,
		IP_TYPE_ANY = IP::TYPE_ANY,
	};

	enum ErrorCode : int64_t {
		OK = Error::OK,
		ERR_NO_RESPONSE = Error::ERR_PRINTER_ON_FIRE + 1,
		ERR_NOT_CONNECTED,
		ERR_PACKET_LENGTH_MISMATCH,
		ERR_SERVER_PROTOCOL_INCOMPATIBLE,
		ERR_CLIENT_PROTOCOL_INCOMPATIBLE,
		ERR_SEQUENCE_MISMATCH,
		ERR_AUTH_PLUGIN_NOT_SET,
		ERR_AUTH_PLUGIN_INCOMPATIBLE,
		ERR_AUTH_FAILED,
		ERR_USERNAME_EMPTY,
		ERR_PASSWORD_EMPTY,
		ERR_DB_NAME_EMPTY,
		ERR_PASSWORD_HASH_LENGTH,
		ERR_INVALID_HOSTNAME,
		ERR_CONNECTION_ERROR,
		ERR_INIT_ERROR,
		ERR_UNAVAILABLE,
		ERR_PROTOCOL_MISMATCH,
		ERR_AUTH_PROTOCOL_MISMATCH,
		ERR_SEND_FAILED,
		ERR_INVALID_PORT,
		ERR_UNKNOWN,
		ERR_PACKET,
		ERR_INVALID_PARAMETER,
		ERR_PREPARE_FAILED,
		ERR_EXECUTE_FAILED
	};

	enum FieldType : uint8_t {
		FT_TINYINT,	 // MYSQL_TYPE_TINY (1) - signed 8-bit
		FT_TINYINT_U,  // MYSQL_TYPE_TINY (1 + unsigned flag)
		FT_SHORT,  // MYSQL_TYPE_SHORT (2) - signed 16-bit
		FT_SHORT_U,	 // MYSQL_TYPE_SHORT + unsigned
		FT_INT,	 // MYSQL_TYPE_LONG (3) - signed 32-bit
		FT_INT_U,  // MYSQL_TYPE_LONG + unsigned
		FT_FLOAT,  // MYSQL_TYPE_FLOAT (4)
		FT_DOUBLE,	// MYSQL_TYPE_DOUBLE (5)
		FT_TIMESTAMP,  // MYSQL_TYPE_TIMESTAMP (7)
		FT_BIGINT,	// MYSQL_TYPE_LONGLONG (8) - signed 64-bit
		FT_BIGINT_U,  // MYSQL_TYPE_LONGLONG + unsigned
		FT_MEDIUMINT,  // MYSQL_TYPE_INT24 (9) - signed 24-bit (rare)
		FT_MEDIUMINT_U,	 // MYSQL_TYPE_INT24 + unsigned
		FT_DATE,  // MYSQL_TYPE_DATE (10)
		FT_TIME,  // MYSQL_TYPE_TIME (11)
		FT_DATETIME,  // MYSQL_TYPE_DATETIME (12)
		FT_YEAR,  // MYSQL_TYPE_YEAR (13)
		FT_NEWDATE,	 // MYSQL_TYPE_NEWDATE (14) - deprecated alias
		FT_VARCHAR,	 // MYSQL_TYPE_VARCHAR (15)
		FT_BIT,	 // MYSQL_TYPE_BIT (16)
		FT_JSON,  // MYSQL_TYPE_JSON (245)
		FT_DECIMAL,	 // MYSQL_TYPE_NEWDECIMAL (246)
		FT_ENUM,  // MYSQL_TYPE_ENUM (247)
		FT_SET,	 // MYSQL_TYPE_SET (248)
		FT_TINYBLOB,  // MYSQL_TYPE_TINY_BLOB (249)
		FT_MEDIUMBLOB,	// MYSQL_TYPE_MEDIUM_BLOB (250)
		FT_LONGBLOB,  // MYSQL_TYPE_LONG_BLOB (251)
		FT_BLOB,  // MYSQL_TYPE_BLOB (252)
		FT_VAR_STRING,	// MYSQL_TYPE_VAR_STRING (253)
		FT_STRING,	// MYSQL_TYPE_STRING (254)
		FT_GEOMETRY	 // MYSQL_TYPE_GEOMETRY (255)
	};

private:
	//https://mariadb.com/kb/en/connection/#capabilities
	enum class Capabilities : uint64_t {
		LONG_PASSWORD = (1ULL << 0),  //MySQL
		CLIENT_MYSQL = (1ULL << 0),	 //MariaDB - lets server know this is a mysql client
		FOUND_ROWS = (1ULL << 1),
		LONG_FLAG = (1ULL << 2),  //Not listed in MariaDB
		CONNECT_WITH_DB = (1ULL << 3),
		NO_SCHEMA = (1ULL << 4),  //Not listed in MariaDB
		NO_DB_TABLE_COLUMN = (1ULL << 4),  //Alternate name, Not listed in MariaDB
		COMPRESS = (1ULL << 5),
		ODBC = (1ULL << 6),	 //Not listed in MariaDB
		LOCAL_FILES = (1ULL << 7),
		IGNORE_SPACE = (1ULL << 8),
		CLIENT_PROTOCOL_41 = (1ULL << 9),
		CLIENT_INTERACTIVE = (1ULL << 10),
		SSL = (1ULL << 11),
		IGNORE_SIGPIPE = (1ULL << 12),	//MySQL
		TRANSACTIONS_MARIA = (1ULL << 12),	//MariaDB
		TRANSACTIONS_MYSQL = (1ULL << 13),	//MySQL
		SECURE_CONNECTION = (1ULL << 13),  //MariaDB
		RESERVED = (1ULL << 14),  //Not listed in MariaDB
		RESERVED2 = (1ULL << 15),  //Not in Maria Docs but needed
		MULTI_STATEMENTS = (1ULL << 16),
		MULTI_RESULTS = (1ULL << 17),
		PS_MULTI_RESULTS = (1ULL << 18),
		PLUGIN_AUTH = (1ULL << 19),
		CLIENT_SEND_CONNECT_ATTRS = (1ULL << 20),
		PLUGIN_AUTH_LENENC_CLIENT_DATA = (1ULL << 21),	//TODO Add compatibility
		CAN_HANDLE_EXPIRED_PASSWORDS = (1ULL << 22),  //Not listed in MariaDB
		SESSION_TRACK = (1ULL << 23),
		CLIENT_DEPRECATE_EOF = (1ULL << 24),
		OPTIONAL_RESULTSET_METADATA = (1ULL << 25),
		CLIENT_ZSTD_COMPRESSION_ALGORITHM = (1ULL << 26),
		CLIENT_QUERY_ATTRIBUTES = (1ULL << 27),	 //Not listed in MariaDB
		//NOT_USED = (1ULL << 28),
		CLIENT_CAPABILITY_EXTENSION = (1ULL << 29),	 //MariaDB reserved for future use.
		SSL_VERIFY_SERVER_CERT = (1ULL << 30),	//Not listed in MariaDB
		REMEMBER_OPTIONS = (1ULL << 31),  //Not listed in MariaDB
		MARIADB_CLIENT_PROGRESS = (1ULL << 32),
		MARIADB_CLIENT_COM_MULTI = (1ULL << 33),
		MARIADB_CLIENT_STMT_BULK_OPERATIONS = (1ULL << 34),
		MARIADB_CLIENT_EXTENDED_TYPE_INFO = (1ULL << 35),
		MARIADB_CLIENT_CACHE_METADATA = (1ULL << 36)
	};

	const String kAuthTypeNamesStr = "client_ed25519,mysql_native_password";
	const PackedStringArray kAuthTypeNames = kAuthTypeNamesStr.split(",");
	bool _dbl_to_string = false;
	IpType _ip_type = IpType::IP_TYPE_ANY;
	AuthType _client_auth_type = AUTH_TYPE_ED25519;
	bool _authenticated = false;
	uint64_t _client_capabilities = 0;
	uint64_t _server_capabilities = 0;

	PackedByteArray _username;
	PackedByteArray _password_hashed;
	PackedByteArray _dbname;

	Ref<StreamPeerTCP> _stream;
	Mutex* _stream_mutex = nullptr;
	String _ip;
	int _port = 0;
	uint32_t _server_timout_msec = 1000;

	// bool _running = true;
	// bool _tcp_polling;
	// Mutex _tcp_mutex;
	// std::thread _tcp_thread;
	// PackedByteArray _tcp_thread_data;

	String _protocol_ver;
	String _server_ver_str;
	uint8_t _srvr_major_ver = 0;
	uint8_t _srvr_minor_ver = 0;
	ErrorCode _last_error = OK;
	PackedByteArray _last_query_converted;
	PackedByteArray _last_transmitted;
	PackedByteArray _last_response;

	/**
	 * \brief			Adds the packet size and sequence number to the beginning of the packet,
	 *					it must be used once just before sending stream to server.
	 * \param stream	std::vector<uint8_t> the stream to be modified.
	 * \param sequance	int
	 */
	void _add_packet_header(PackedByteArray& p_pkt, uint8_t p_pkt_seq);

	// void m_append_thread_data(PackedByteArray &p_data, const uint64_t p_timeout = 1000);
	// void m_tcp_thread_func();

	ErrorCode _client_protocol_v41(const AuthType p_srvr_auth_type, const PackedByteArray p_srvr_salt);
	ErrorCode _connect();
	PackedByteArray _get_pkt_bytes_adv_idx(const PackedByteArray& src_buf, size_t& start_pos, const size_t byte_cnt);
	AuthType _get_server_auth_type(String p_srvr_auth_name);
	Variant _get_type_data(const int p_db_field_type, const PackedByteArray& p_data, const int p_char_set);
	void _handle_server_error(const PackedByteArray p_src_buffer, size_t& p_last_pos);
	void _hash_password(String p_password);
	TypedArray<Dictionary> _parse_prepared_exec(PackedByteArray& buf,
												size_t& pkt_itr,
												const TypedArray<Dictionary>& col_defs,
												bool dep_eof);
	TypedArray<Dictionary> _parse_string_rows(PackedByteArray& buf,
											  size_t& pkt_itr,
											  const TypedArray<Dictionary>& col_defs,
											  const bool dep_eof);
	String _parse_null_utf8_at_adv_idx(PackedByteArray p_buf, size_t& p_start_pos);
	String _parse_null_utf8(PackedByteArray p_buf);
	ErrorCode _prepared_params_send(const uint32_t stmt_id, const TypedArray<Dictionary>& params);
	Variant _query(const String& sql_stmt, const bool is_command = false);
	ErrorCode _rcv_bfr_chk(PackedByteArray& bfr, int& bfr_size, const size_t cur_pos, const size_t bytes_needed);
	PackedByteArray _read_buffer(uint32_t timeout, uint32_t expected_bytes = 0);
	TypedArray<Dictionary> _read_columns_data(PackedByteArray& srvr_response, size_t& pkt_itr, const uint16_t col_cnt);
	//TODO(sigrudds1) Add error log file using the username in the filename
	ErrorCode _server_init_handshake_v10(const PackedByteArray& p_src_buffer);
	Variant _com_query_response(const bool p_is_command);
	void _update_username(String P_username);

protected:
	static void _bind_methods();
	Dictionary _prep_column_data;
	enum MySqlFieldType : uint8_t {
		MYSQL_TYPE_DECIMAL = 0,
		MYSQL_TYPE_TINY = 1,
		MYSQL_TYPE_SHORT = 2,
		MYSQL_TYPE_LONG = 3,
		MYSQL_TYPE_FLOAT = 4,
		MYSQL_TYPE_DOUBLE = 5,
		MYSQL_TYPE_NULL = 6,
		MYSQL_TYPE_TIMESTAMP = 7,
		MYSQL_TYPE_LONGLONG = 8,
		MYSQL_TYPE_INT24 = 9,
		MYSQL_TYPE_DATE = 10,
		MYSQL_TYPE_TIME = 11,
		MYSQL_TYPE_DATETIME = 12,
		MYSQL_TYPE_YEAR = 13,
		MYSQL_TYPE_NEWDATE = 14,
		MYSQL_TYPE_VARCHAR = 15,
		MYSQL_TYPE_BIT = 16,
		MYSQL_TYPE_JSON = 245,
		MYSQL_TYPE_NEWDECIMAL = 246,
		MYSQL_TYPE_ENUM = 247,
		MYSQL_TYPE_SET = 248,
		MYSQL_TYPE_TINY_BLOB = 249,
		MYSQL_TYPE_MEDIUM_BLOB = 250,
		MYSQL_TYPE_LONG_BLOB = 251,
		MYSQL_TYPE_BLOB = 252,
		MYSQL_TYPE_VAR_STRING = 253,
		MYSQL_TYPE_STRING = 254,
		MYSQL_TYPE_GEOMETRY = 255
	};
	enum Sign : uint8_t {
		SIGN_SIGNED = 0x00,
		SIGN_UNSIGNED = 0x80

	};

public:
	/**
	 * \brief				This method sets the authentication type used.
	 *
	 * \param host
	 * \param port
	 * \param dbname
	 * \param username
	 * \param password
	 * \param auth_type		enum AuthType determines what authoriztion type will be statically used.
	 * \param is_pre_hash	bool if set the password used will be hashed by the required type before used.
	 * \return 				uint32_t 0 = no error, see error enum class ErrorCode
	 */
	ErrorCode connect_db(const String& host,
						 const int port,
						 const String& dbname,
						 const String& username,
						 const String& password,
						 const AuthType auth_type = AuthType::AUTH_TYPE_ED25519,
						 bool is_prehashed = true);

	ErrorCode connect_db_ctx(const Ref<MariaDBConnectContext>& p_context);
	void disconnect_db();
	Dictionary excecute_command(const String& sql_stmt);
	static Ref<MariaDBConnector> connection_instance(const Ref<MariaDBConnectContext>& p_context);
	ErrorCode get_last_error() const { return _last_error; }
	PackedByteArray get_last_query_converted();
	PackedByteArray get_last_response();
	PackedByteArray get_last_transmitted();

	// PackedByteArray get_caching_sha2_passwd_hash(PackedByteArray p_sha256_hashed_passwd, PackedByteArray
	// p_srvr_salt);
	PackedByteArray get_client_ed25519_signature(const PackedByteArray& p_sha512_hashed_passwd,
												 const PackedByteArray& p_svr_msg);
	PackedByteArray get_mysql_native_password_hash(const PackedByteArray& p_sha1_hashed_passwd,
												   const PackedByteArray& p_srvr_salt);

	bool is_connected_db();

	Variant query(const String& sql_stmt) { return _query(sql_stmt); }
	void ping_srvr();
	// Prepared statement section
	Dictionary prepared_statement(const String& sql);
	TypedArray<Dictionary> prepared_stmt_exec_select(uint32_t stmt_id, const TypedArray<Dictionary>& params);
	// TypedArray<Dictionary> exec_prepped_select(uint32_t stmt_id, const Array &params);
	Dictionary prepared_stmt_exec_cmd(uint32_t stmt_id, const TypedArray<Dictionary>& params);
	ErrorCode prepared_statement_close(uint32_t stmt_id);

	TypedArray<Dictionary> select_query(const String& sql_stmt);

	//TODO(sigrudds1) Implement SSL/TLS
	//void tls_enable(bool enable);

	void set_dbl_to_string(bool is_to_str);
	void set_db_name(String p_db_name);
	void set_ip_type(IpType p_type);
	void set_server_timeout(uint32_t msec = 1000) { _server_timout_msec = msec; }
	// TODO(sigrudds1) Async Callbacks signals

	MariaDBConnector();
	~MariaDBConnector();
};

VARIANT_ENUM_CAST(MariaDBConnector::AuthType);
VARIANT_ENUM_CAST(MariaDBConnector::IpType);
VARIANT_ENUM_CAST(MariaDBConnector::ErrorCode);
VARIANT_ENUM_CAST(MariaDBConnector::FieldType);
