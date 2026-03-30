/*************************************************************************/
/*  mariadb.cpp                                                          */
/*************************************************************************/
/*                     This file is part of the                          */
/*                     MariaDB connection module                         */
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

#include "mariadb_connector.hpp"

#include "ed25519_ref10/ed25519_auth.h"
#include "mariadb_conversions.hpp"
#include "mbedtls/sha1.h"
#include "mbedtls/sha512.h"

#include <godot_cpp/classes/marshalls.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/classes/time.hpp>
#include <godot_cpp/core/memory.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

using namespace godot;

static uint64_t _decode_lenenc_adv_itr(const PackedByteArray& p_buf, size_t& p_pkt_idx) {
	uint8_t marker = p_buf[p_pkt_idx++];
	if (marker < 0xFB) {
		return marker;
	} else if (marker == 0xFB /* NULL */) {
		// Can't return NULL but len will not be larger than FFFFFFFFFFFFFFFE so we can test for UINT64_MAX
		return UINT64_MAX;
	} else if (marker == 0xFC) {
		uint64_t v = p_buf[p_pkt_idx++];
		v |= uint64_t(p_buf[p_pkt_idx++]) << 8;
		return v;
	} else if (marker == 0xFD) {
		uint64_t v = p_buf[p_pkt_idx++];
		v |= uint64_t(p_buf[p_pkt_idx++]) << 8;
		v |= uint64_t(p_buf[p_pkt_idx++]) << 16;
		return v;
	} else if (marker == 0xFE) {
		uint64_t v = uint64_t(p_buf[p_pkt_idx++]);
		v |= uint64_t(p_buf[p_pkt_idx++]) << 8;
		v |= uint64_t(p_buf[p_pkt_idx++]) << 16;
		v |= uint64_t(p_buf[p_pkt_idx++]) << 24;
		uint64_t hi = uint64_t(p_buf[p_pkt_idx++]);
		hi |= uint64_t(p_buf[p_pkt_idx++]) << 8;
		hi |= uint64_t(p_buf[p_pkt_idx++]) << 16;
		hi |= uint64_t(p_buf[p_pkt_idx++]) << 24;
		return (hi << 32) | v;
	}
	return marker;
}

static inline bool is_valid_hex(const String& p_string, int expected_length = 0) {
	if (expected_length > 0 && p_string.length() != expected_length) {
		return false;
	}

	for (int i = 0; i < p_string.length(); i++) {
		char32_t c = p_string.unicode_at(i);
		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static inline PackedByteArray _sha1(const PackedByteArray& p_data) {
	PackedByteArray output;
	output.resize(20);

	mbedtls_sha1_context ctx;
	mbedtls_sha1_init(&ctx);
	mbedtls_sha1_starts(&ctx);
	mbedtls_sha1_update(&ctx, p_data.ptr(), p_data.size());
	mbedtls_sha1_finish(&ctx, output.ptrw());
	mbedtls_sha1_free(&ctx);

	return output;
}

MariaDBConnector::MariaDBConnector() {
	_stream.instantiate();
	_stream_mutex = memnew(Mutex);
}

MariaDBConnector::~MariaDBConnector() {
	disconnect_db();
	if (_stream_mutex) {
		_stream_mutex->~Mutex();
		internal::gdextension_interface_mem_free(_stream_mutex);
		_stream_mutex = nullptr;
	}
}

// Bind all your methods used in this class
void MariaDBConnector::_bind_methods() {
	ClassDB::bind_method(
			D_METHOD("connect_db", "hostname", "port", "database", "username", "password", "authtype", "is_prehashed"),
			&MariaDBConnector::connect_db,
			DEFVAL(AUTH_TYPE_ED25519),
			DEFVAL(true));
	ClassDB::bind_method(D_METHOD("connect_db_ctx", "mariadb_connect_context"), &MariaDBConnector::connect_db_ctx);
	ClassDB::bind_static_method("MariaDBConnector",
								D_METHOD("connection_instance", "mariadb_connect_context"),
								&MariaDBConnector::connection_instance);
	ClassDB::bind_method(D_METHOD("disconnect_db"), &MariaDBConnector::disconnect_db);
	ClassDB::bind_method(D_METHOD("execute_command", "sql_stmt"), &MariaDBConnector::excecute_command);
	ClassDB::bind_method(D_METHOD("get_last_query_converted"), &MariaDBConnector::get_last_query_converted);
	ClassDB::bind_method(D_METHOD("get_last_response"), &MariaDBConnector::get_last_response);
	ClassDB::bind_method(D_METHOD("get_last_transmitted"), &MariaDBConnector::get_last_transmitted);
	ClassDB::bind_method(D_METHOD("get_last_error"), &MariaDBConnector::get_last_error);
	ClassDB::bind_method(D_METHOD("get_last_error_code"), &MariaDBConnector::get_last_error);
	ClassDB::bind_method(D_METHOD("is_connected_db"), &MariaDBConnector::is_connected_db);
	ClassDB::bind_method(D_METHOD("select_query", "sql_stmt"), &MariaDBConnector::select_query);
	ClassDB::bind_method(D_METHOD("query", "sql_stmt"), &MariaDBConnector::query);
	ClassDB::bind_method(D_METHOD("ping_srvr"), &MariaDBConnector::ping_srvr);

	ClassDB::bind_method(D_METHOD("prep_stmt", "sql"), &MariaDBConnector::prepared_statement);
	ClassDB::bind_method(D_METHOD("prep_stmt_exec_select", "stmt_id", "params"),
						 &MariaDBConnector::prepared_stmt_exec_select);
	ClassDB::bind_method(D_METHOD("prep_stmt_exec_cmd", "stmt_id", "params"),
						 &MariaDBConnector::prepared_stmt_exec_cmd);
	ClassDB::bind_method(D_METHOD("prep_stmt_close", "stmt_id"), &MariaDBConnector::prepared_statement_close);

	ClassDB::bind_method(D_METHOD("set_dbl_to_string", "is_to_str"), &MariaDBConnector::set_dbl_to_string);
	ClassDB::bind_method(D_METHOD("set_db_name", "db_name"), &MariaDBConnector::set_db_name);
	ClassDB::bind_method(D_METHOD("set_ip_type", "type"), &MariaDBConnector::set_ip_type);
	ClassDB::bind_method(D_METHOD("set_server_timeout", "msec"), &MariaDBConnector::set_server_timeout, DEFVAL(1000));

	ADD_PROPERTY(PropertyInfo(Variant::INT, "is_connected_db"), "", "is_connected_db");
	ADD_PROPERTY(PropertyInfo(Variant::INT, "last_error"), "", "get_last_error_code");

	BIND_ENUM_CONSTANT(IP_TYPE_IPV4);
	BIND_ENUM_CONSTANT(IP_TYPE_IPV6);
	BIND_ENUM_CONSTANT(IP_TYPE_ANY);

	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);
	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);

	BIND_ENUM_CONSTANT(OK);
	BIND_ENUM_CONSTANT(ERR_NO_RESPONSE);
	BIND_ENUM_CONSTANT(ERR_NOT_CONNECTED);
	BIND_ENUM_CONSTANT(ERR_PACKET_LENGTH_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_SERVER_PROTOCOL_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_CLIENT_PROTOCOL_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_SEQUENCE_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_AUTH_PLUGIN_NOT_SET);
	BIND_ENUM_CONSTANT(ERR_AUTH_PLUGIN_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_AUTH_FAILED);
	BIND_ENUM_CONSTANT(ERR_USERNAME_EMPTY);
	BIND_ENUM_CONSTANT(ERR_PASSWORD_EMPTY);
	BIND_ENUM_CONSTANT(ERR_DB_NAME_EMPTY);
	BIND_ENUM_CONSTANT(ERR_PASSWORD_HASH_LENGTH);
	BIND_ENUM_CONSTANT(ERR_INVALID_HOSTNAME);
	BIND_ENUM_CONSTANT(ERR_CONNECTION_ERROR);
	BIND_ENUM_CONSTANT(ERR_INIT_ERROR);
	BIND_ENUM_CONSTANT(ERR_UNAVAILABLE);
	BIND_ENUM_CONSTANT(ERR_PROTOCOL_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_AUTH_PROTOCOL_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_SEND_FAILED);
	BIND_ENUM_CONSTANT(ERR_INVALID_PORT);
	BIND_ENUM_CONSTANT(ERR_UNKNOWN);
	BIND_ENUM_CONSTANT(ERR_PACKET);
	BIND_ENUM_CONSTANT(ERR_PREPARE_FAILED);

	BIND_ENUM_CONSTANT(FT_TINYINT);
	BIND_ENUM_CONSTANT(FT_TINYINT_U);
	BIND_ENUM_CONSTANT(FT_SHORT);
	BIND_ENUM_CONSTANT(FT_SHORT_U);
	BIND_ENUM_CONSTANT(FT_INT);
	BIND_ENUM_CONSTANT(FT_INT_U);
	BIND_ENUM_CONSTANT(FT_FLOAT);
	BIND_ENUM_CONSTANT(FT_DOUBLE);
	BIND_ENUM_CONSTANT(FT_TIMESTAMP);
	BIND_ENUM_CONSTANT(FT_BIGINT);
	BIND_ENUM_CONSTANT(FT_BIGINT_U);
	BIND_ENUM_CONSTANT(FT_MEDIUMINT);
	BIND_ENUM_CONSTANT(FT_MEDIUMINT_U);
	BIND_ENUM_CONSTANT(FT_DATE);
	BIND_ENUM_CONSTANT(FT_TIME);
	BIND_ENUM_CONSTANT(FT_DATETIME);
	BIND_ENUM_CONSTANT(FT_YEAR);
	BIND_ENUM_CONSTANT(FT_NEWDATE);
	BIND_ENUM_CONSTANT(FT_VARCHAR);
	BIND_ENUM_CONSTANT(FT_BIT);
	BIND_ENUM_CONSTANT(FT_JSON);
	BIND_ENUM_CONSTANT(FT_DECIMAL);
	BIND_ENUM_CONSTANT(FT_ENUM);
	BIND_ENUM_CONSTANT(FT_SET);
	BIND_ENUM_CONSTANT(FT_TINYBLOB);
	BIND_ENUM_CONSTANT(FT_MEDIUMBLOB);
	BIND_ENUM_CONSTANT(FT_LONGBLOB);
	BIND_ENUM_CONSTANT(FT_BLOB);
	BIND_ENUM_CONSTANT(FT_VAR_STRING);
	BIND_ENUM_CONSTANT(FT_STRING);
	BIND_ENUM_CONSTANT(FT_GEOMETRY);
}

// Custom Functions
// private
void MariaDBConnector::_add_packet_header(PackedByteArray& p_pkt, uint8_t p_pkt_seq) {
	PackedByteArray t = little_endian_to_vbytes(p_pkt.size(), 3);
	t.push_back(p_pkt_seq);
	t.append_array(p_pkt);
	p_pkt = t.duplicate();
}

MariaDBConnector::ErrorCode MariaDBConnector::_client_protocol_v41(const AuthType p_srvr_auth_type,
																   const PackedByteArray p_srvr_salt) {
	PackedByteArray srvr_response_pba;
	PackedByteArray srvr_auth_msg_pba;
	uint8_t seq_num = 0;
	AuthType user_auth_type = AUTH_TYPE_ED25519;

	// Per https://mariadb.com/kb/en/connection/#handshake-response-packet
	// int<4> client capabilities
	_client_capabilities = 0;
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL);
	// client_capabilities |= (uint64_t)Capabilities::FOUND_ROWS;
	_client_capabilities |= (uint64_t)Capabilities::LONG_FLAG;	//??
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB);
	_client_capabilities |= (uint64_t)Capabilities::LOCAL_FILES;
	_client_capabilities |= (uint64_t)Capabilities::CLIENT_PROTOCOL_41;
	_client_capabilities |= (uint64_t)Capabilities::CLIENT_INTERACTIVE;
	_client_capabilities |= (uint64_t)Capabilities::SECURE_CONNECTION;

	// Not listed in MariaDB docs but if not set it won't parse the stream
	// correctly
	_client_capabilities |= (uint64_t)Capabilities::RESERVED2;

	_client_capabilities |= (uint64_t)Capabilities::MULTI_STATEMENTS;
	_client_capabilities |= (uint64_t)Capabilities::MULTI_RESULTS;
	_client_capabilities |= (uint64_t)Capabilities::PS_MULTI_RESULTS;
	_client_capabilities |= (uint64_t)Capabilities::PLUGIN_AUTH;

	// Don't think this is needed for game dev needs, maybe for prepared
	// statements? _client_capabilities |= (_server_capabilities &
	// (uint64_t)Capabilities::CLIENT_SEND_CONNECT_ATTRS);

	_client_capabilities |= (uint64_t)Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS;  //??
	_client_capabilities |= (uint64_t)Capabilities::SESSION_TRACK;
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);
	_client_capabilities |= (uint64_t)Capabilities::REMEMBER_OPTIONS;  //??

	// Only send the first 4 bytes(32 bits) of capabilities the remaining will be
	// sent later in another 4 byte
	PackedByteArray send_buffer_pba = little_endian_to_vbytes(_client_capabilities, 4);
	// printf("_client_cap %ld", _client_capabilities);

	// int<4> max packet size
	// temp_vec = little_endian_bytes((uint32_t)0x40000000, 4);
	// send_buffer_vec.insert(send_buffer_vec.end(), temp_vec.begin(),
	// temp_vec.end());
	send_buffer_pba.append_array(little_endian_to_vbytes((uint32_t)0x40000000, 4));

	// TODO Find Collation list, create enum and setter
	//  int<1> client character collation
	send_buffer_pba.push_back(33);	// utf8_general_ci

	// string<19> reserved
	// send_buffer_vec.insert(send_buffer_vec.end(), 19, 0);
	PackedByteArray temp_pba;
	temp_pba.resize(19);
	temp_pba.fill(0);
	send_buffer_pba.append_array(temp_pba);

	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) && _srvr_major_ver >= 10 &&
		_srvr_minor_ver >= 2) {
		// TODO implement Extended capabilities, if needed, this will result in more
		// data between _client_capabilities |= (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_PROGRESS); _client_capabilities |=
		// (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_COM_MULTI); _client_capabilities
		// |= (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_STMT_BULK_OPERATIONS);
		// _client_capabilities |= (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_EXTENDED_TYPE_INFO);

		// we need the metadata in the stream so we can form the dictionary ??
		_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_CACHE_METADATA);
		// int<4> extended client capabilities
		temp_pba = little_endian_to_vbytes(_client_capabilities, 4, 4);
		send_buffer_pba.append_array(temp_pba);
	} else {
		// string<4> reserved
		temp_pba.resize(4);
		temp_pba.fill(0);
		send_buffer_pba.append_array(temp_pba);
	}

	// string<NUL> username
	send_buffer_pba.append_array(_username);
	send_buffer_pba.push_back(0);  // NUL terminated

	PackedByteArray auth_response_pba;
	if (p_srvr_auth_type == AUTH_TYPE_MYSQL_NATIVE && (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE)) {
		auth_response_pba = get_mysql_native_password_hash(_password_hashed, p_srvr_salt);
	}

	// if (server_capabilities & PLUGIN_AUTH_LENENC_CLIENT_DATA)
	// string<lenenc> authentication data
	// else if (server_capabilities & SECURE_CONNECTION) //mysql uses secure
	// connection flag for transactions
	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) &&
		(_server_capabilities & (uint64_t)Capabilities::SECURE_CONNECTION)) {
		// int<1> length of authentication response
		send_buffer_pba.push_back((uint8_t)auth_response_pba.size());
		// string<fix> authentication response
		send_buffer_pba.append_array(auth_response_pba);
	} else {
		// else string<NUL> authentication response null ended
		send_buffer_pba.append_array(auth_response_pba);
		send_buffer_pba.push_back(0);  // NUL terminated
	}

	// if (server_capabilities & CLIENT_CONNECT_WITH_DB)
	// string<NUL> default database name
	if (_client_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB) {
		send_buffer_pba.append_array(_dbname);
		send_buffer_pba.push_back(0);  // NUL terminated
	}

	// if (server_capabilities & CLIENT_PLUGIN_AUTH)
	// string<NUL> authentication plugin name
	PackedByteArray auth_plugin_name_pba = kAuthTypeNames[(size_t)AUTH_TYPE_MYSQL_NATIVE].to_ascii_buffer();
	send_buffer_pba.append_array(auth_plugin_name_pba);
	send_buffer_pba.push_back(0);  // NUL terminated

	// Implementing CLIENT_SEND_CONNECT_ATTRS will just add more data, I don't
	// think it is needed for game dev use if (server_capabilities &
	// CLIENT_SEND_CONNECT_ATTRS) int<lenenc> size of connection attributes while
	// packet has remaining data string<lenenc> key string<lenenc> value

	_add_packet_header(send_buffer_pba, ++seq_num);
	_last_error = (ErrorCode)_stream->put_data(send_buffer_pba);
	if (_last_error != OK) return _last_error;

	srvr_response_pba = _read_buffer(_server_timout_msec);
	size_t itr = 4;

	if (srvr_response_pba.size() > 0) {
		// 4th byte is seq should be 2
		seq_num = srvr_response_pba[3];
		// 5th byte is status
		uint8_t status = srvr_response_pba[itr];
		if (status == 0x00) {
			_authenticated = true;
			return ErrorCode::OK;
		} else if (status == 0xFE) {
			user_auth_type = _get_server_auth_type(_parse_null_utf8_at_adv_idx(srvr_response_pba, itr));
		} else if (status == 0xFF) {
			_handle_server_error(srvr_response_pba, itr);
			_authenticated = false;
			return ErrorCode::ERR_AUTH_FAILED;
		} else {
			ERR_FAIL_V_EDMSG(ErrorCode::ERR_UNKNOWN,
							 "Unhandled response code:" + String::num_uint64(srvr_response_pba[itr], 16, true));
		}
	}

	if (user_auth_type == AUTH_TYPE_ED25519 && _client_auth_type == AUTH_TYPE_ED25519) {
		// srvr_auth_msg.assign(srvr_response.begin() + itr + 1,
		// srvr_response.end());
		srvr_auth_msg_pba.append_array(srvr_response_pba.slice(itr + 1));
		auth_response_pba = get_client_ed25519_signature(_password_hashed, srvr_auth_msg_pba);
		send_buffer_pba = auth_response_pba;
	} else {
		return ErrorCode::ERR_AUTH_PROTOCOL_MISMATCH;
	}

	_add_packet_header(send_buffer_pba, ++seq_num);

	_last_error = (ErrorCode)_stream->put_data(send_buffer_pba);
	if (_last_error != OK) {
		ERR_PRINT("Failed to put data!");
		return _last_error;
	}

	srvr_response_pba = _read_buffer(_server_timout_msec);

	if (srvr_response_pba.size() > 0) {
		// 4th byte is seq should be 2
		seq_num = srvr_response_pba[3];
		// 5th byte is status
		itr = 4;
		if (srvr_response_pba[itr] == 0x00) {
			_authenticated = true;
		} else if (srvr_response_pba[itr] == 0xFF) {
			_handle_server_error(srvr_response_pba, itr);
			_authenticated = false;
			return ErrorCode::ERR_AUTH_FAILED;
		} else {
			ERR_FAIL_V_MSG(ErrorCode::ERR_UNKNOWN,
						   "Unhandled response code:" + String::num_uint64(srvr_response_pba[itr], 16, true));
		}
	}

	return ErrorCode::OK;
}

Variant MariaDBConnector::_com_query_response(const bool p_is_command) {
	/* For interest of speed over memory I am working with the entire buffer
	 * and keeping track of the iteration point, as most queries for
	 * game dev should be small but speedy.
	 */
	// From MariaDBConnector version 10.2 dep_eof should be true

	PackedByteArray srvr_response = _read_buffer(_server_timout_msec);
	// m_append_thread_data(srvr_response);

	if (srvr_response.size() == 0) {
		_last_error = ErrorCode::ERR_NO_RESPONSE;
		if (p_is_command) {
			return 0;
		} else {
			return (uint32_t)ErrorCode::ERR_NO_RESPONSE;
		}
	}

	size_t pkt_idx = 0;
	// Not doing anything with this value, here, because the buffer may have been
	// full and more data is needed. So I am using the process time to allow more
	// to get into the buffer, instead of constantly polling the buffer
	//	before any work is done, there are more and smaller internal packets
	// with buffer size checks for every 	sub-packet.
	size_t pkt_len = bytes_to_num_adv_itr<size_t>(srvr_response.ptr(), 3, pkt_idx);

	// uint8_t seq_num = srvr_response[pkt_idx++];
	pkt_idx++;
	/* https://mariadb.com/kb/en/result-set-packets/
	 * The pkt_idx should be at 3, we are on the 4th byte and wlll iterate before
	 * use Resultset metadata All segment packets start with packet length(3
	 * bytes) and sequence number This is a small packet with packet length of 1
	 * to 9 of 4 to 19 bytes to determine how many columns of data are being sent.
	 */

	uint64_t col_cnt = 0;
	uint8_t marker = srvr_response[pkt_idx];
	// https://mariadb.com/kb/en/protocol-data-types/#length-encoded-integers
	if (marker == 0xFF) {
		_handle_server_error(srvr_response, pkt_idx);
		_last_error = ErrorCode::ERR_PACKET;

		if (p_is_command) {
			return 0;
		} else {
			return (uint32_t)_last_error;
		}
	} else if (marker == 0x00) {
		if (p_is_command) {
			pkt_idx++;
			Dictionary result;

			uint64_t affected_rows = _decode_lenenc_adv_itr(srvr_response, pkt_idx);
			uint64_t last_insert_id = _decode_lenenc_adv_itr(srvr_response, pkt_idx);
			uint16_t status_flags = srvr_response[pkt_idx++] | (srvr_response[pkt_idx++] << 8);
			uint16_t warnings = srvr_response[pkt_idx++] | (srvr_response[pkt_idx++] << 8);

			// Info message
			String info_message = "";
			if (pkt_idx + 1 < srvr_response.size()) {
				info_message =
						String::utf8((const char*)&srvr_response[pkt_idx + 1], srvr_response.size() - (pkt_idx + 1));
			}

			// Build dictionary
			result["affected_rows"] = affected_rows;
			result["last_insert_id"] = last_insert_id;
			result["status_flags"] = status_flags;
			result["warnings"] = warnings;
			result["info"] = info_message;

			return result;
		}
		return 0;
	} else if (marker == 0xFB) {
		// LOCAL_INFILE Packet if the query was "LOCAL INFILE
		// https://mariadb.com/kb/en/packet_local_infile/
	} else {
		col_cnt = _decode_lenenc_adv_itr(srvr_response, pkt_idx);
	}

	if (_client_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_CACHE_METADATA) {
		pkt_idx++;
	}

	TypedArray<Dictionary> col_data = _read_columns_data(srvr_response, pkt_idx, col_cnt);
	//	if not (CLIENT_DEPRECATE_EOF capability set) get EOF_Packet
	bool dep_eof = (_client_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);
	if (!dep_eof) {
		pkt_idx += 5;  // bypass for now
	}

	_last_response = PackedByteArray(srvr_response);
	TypedArray<Dictionary> rows = _parse_string_rows(srvr_response, pkt_idx, col_data, dep_eof);

	return Variant(rows);
}

MariaDBConnector::ErrorCode MariaDBConnector::_connect() {
	disconnect_db();
	_stream_mutex->lock();
	_last_error = (ErrorCode)_stream->connect_to_host(_ip, _port);

	if (_last_error != ErrorCode::OK) {
		ERR_PRINT("Cannot connect to host with IP: " + String(_ip) + " and port: " + itos(_port));
		_stream_mutex->unlock();
		return _last_error;
	}

	for (size_t i = 0; i < 1000; i++) {
		_last_error = (ErrorCode)_stream->poll();
		if (_last_error != OK) return _last_error;
		if (_stream->get_status() == StreamPeerTCP::STATUS_CONNECTED) {
			break;
		} else {
			OS::get_singleton()->delay_usec(1000);
		}
	}

	if (_stream->get_status() != StreamPeerTCP::STATUS_CONNECTED) {
		ERR_PRINT("TCP connection not established after polling. IP: " + String(_ip) + " Port: " + itos(_port));
		_stream_mutex->unlock();
		return ErrorCode::ERR_CONNECTION_ERROR;
	}

	PackedByteArray recv_buffer = _read_buffer(_server_timout_msec);
	if (recv_buffer.size() <= 4) {
		ERR_PRINT("connect: Receive buffer empty!");
		_stream_mutex->unlock();
		return ErrorCode::ERR_UNAVAILABLE;
	}

	// per https://mariadb.com/kb/en/connection/
	// The first packet from the server on a connection is a greeting
	// giving/suggesting the requirements to login

	/* Per https://mariadb.com/kb/en/0-packet/
	 * On all packet stages between packet segment the standard packet is sent
	 * int<3> rcvd_bfr[0] to rcvd_bfr[2] First 3 bytes are packet length
	 * int<1> rcvd_bfr[3] 4th byte is sequence number
	 * byte<n> rcvd_bfr[4] to rcvd_bfr[4 + n] remaining bytes are the packet body
	 * n = packet length
	 */

	uint32_t packet_length =
			(uint32_t)recv_buffer[0] + ((uint32_t)recv_buffer[1] << 8) + ((uint32_t)recv_buffer[2] << 16);
	// On initial connect the packet length should be 4 byte less than buffer
	// length
	if (packet_length != ((uint32_t)recv_buffer.size() - 4)) {
		ERR_PRINT("Receive buffer does not match expected size!");
		_stream_mutex->unlock();
		return ErrorCode::ERR_PACKET_LENGTH_MISMATCH;
	}

	// 4th byte is sequence number, increment this when replying with login
	// request, if client starts then start at 0
	if (recv_buffer[3] != 0) {
		ERR_PRINT("Packet sequence error!");
		_stream_mutex->unlock();
		return ErrorCode::ERR_SEQUENCE_MISMATCH;
	}

	// From the 5th byte on is the packet body

	/* 5th byte is protocol version, currently only 10 for MariaDBConnector and
	 * MySQL v3.21.0+, protocol version 9 for older MySQL versions.
	 */

	if (recv_buffer[4] == 10) {
		_server_init_handshake_v10(recv_buffer);
	} else {
		ERR_PRINT("Unsupported protocol version in handshake packet!");
		_stream_mutex->unlock();
		return ErrorCode::ERR_PROTOCOL_MISMATCH;
	}

	// Passing as lambda so external non-static members can be accessed
	// _tcp_thread = std::thread([this] { m_tcp_thread_func(); });
	_stream_mutex->unlock();
	return ErrorCode::OK;
}  // m_connect

Variant MariaDBConnector::_get_type_data(const int p_db_field_type,
										 const PackedByteArray& p_data,
										 const int p_char_set) {
	String rtn_val;
	switch (p_db_field_type) {
		case MYSQL_TYPE_TINY:
		case MYSQL_TYPE_SHORT:	//  aka SMALLINT
		case MYSQL_TYPE_LONG:
		case MYSQL_TYPE_LONGLONG:
		case MYSQL_TYPE_INT24:	// aka MEDIUMINT
		case MYSQL_TYPE_YEAR:  // aka SMALLINT
			rtn_val.parse_utf8((const char*)p_data.ptr(), p_data.size());
			return rtn_val.to_int();
			break;
		case MYSQL_TYPE_DECIMAL:
		case MYSQL_TYPE_FLOAT:
			rtn_val.parse_utf8((const char*)p_data.ptr(), p_data.size());
			return rtn_val.to_float();
			break;
		case MYSQL_TYPE_DOUBLE:
			rtn_val.parse_utf8((const char*)p_data.ptr(), p_data.size());
			if (_dbl_to_string) {
				return rtn_val;
			} else {
				return rtn_val.to_float();
			}
			break;
		default:
			if (p_char_set == 63) {
				return p_data;
			}
			rtn_val.parse_utf8((const char*)p_data.ptr(), p_data.size());
			return rtn_val;
	}
	return 0;
}

MariaDBConnector::AuthType MariaDBConnector::_get_server_auth_type(String p_srvr_auth_name) {
	AuthType server_auth_type = AUTH_TYPE_ED25519;
	if (p_srvr_auth_name == "mysql_native_password") {
		server_auth_type = AUTH_TYPE_MYSQL_NATIVE;
	} else if (p_srvr_auth_name == "client_ed25519") {
		server_auth_type = AUTH_TYPE_ED25519;
	}
	// TODO(sigrudds1) Add cached_sha2 for mysql
	return server_auth_type;
}

void MariaDBConnector::_handle_server_error(const PackedByteArray p_src_buffer, size_t& p_last_pos) {
	// REF https://mariadb.com/kb/en/err_packet/
	uint16_t srvr_error_code = (uint16_t)p_src_buffer[p_last_pos++];
	srvr_error_code += (uint16_t)p_src_buffer[p_last_pos++] << 8;
	String msg = String::num_uint64((uint64_t)srvr_error_code) + " - ";
	if (srvr_error_code == 0xFFFF) {
		// int<1> stage
		// int<1> max_stage
		// int<3> progress
		// string<lenenc> progress_info
	} else {
		if (p_src_buffer[p_last_pos] == '#') {
			msg += "SQL State:";
			for (size_t itr = 0; itr < 6; ++itr) msg += (char)p_src_buffer[p_last_pos++];
			msg += " - ";
			while (p_last_pos < (size_t)p_src_buffer.size() - 1) {
				msg += (char)p_src_buffer[p_last_pos++];
			}
		} else {
			// string<EOF> human - readable error message
			while (p_last_pos < (size_t)p_src_buffer.size() - 1) {
				msg += (char)p_src_buffer[p_last_pos++];
			}
		}
	}
	ERR_FAIL_COND_EDMSG(srvr_error_code != OK, msg);
}

String MariaDBConnector::_parse_null_utf8(PackedByteArray p_buf) {
	size_t start_pos = 0;
	return _parse_null_utf8_at_adv_idx(p_buf, start_pos);
}

String MariaDBConnector::_parse_null_utf8_at_adv_idx(PackedByteArray p_buf, size_t& p_start_pos) {
	String str;
	while (p_buf[++p_start_pos] != 0 && p_start_pos < (size_t)p_buf.size()) {
		str += p_buf[p_start_pos];
	}
	return str;
}

PackedByteArray MariaDBConnector::_get_pkt_bytes_adv_idx(const PackedByteArray& p_src_buf,
														 size_t& p_start_pos,
														 const size_t p_byte_cnt) {
	if (p_byte_cnt <= 0 || p_start_pos + p_byte_cnt > (size_t)p_src_buf.size()) {
		return PackedByteArray();
	}

	PackedByteArray rtn;
	for (size_t i = 0; i < p_byte_cnt; ++i) {
		rtn.push_back(p_src_buf[p_start_pos++]);
	}
	return rtn;
}

TypedArray<Dictionary> MariaDBConnector::_parse_prepared_exec(PackedByteArray& p_rx_bfr,
															  size_t& p_pkt_idx,
															  const TypedArray<Dictionary>& p_col_defs,
															  const bool p_dep_eof) {
	const uint32_t col_cnt = p_col_defs.size();
	int bfr_size;

	if (col_cnt == 0) {
		// OK-packet handled in
		return TypedArray<Dictionary>();
	}

	TypedArray<Dictionary> rows;
	const int nullmap_bytes = (col_cnt + 7 + 2) / 8;

	while (true) {
		// Validate packet header presence (first 4 bytes)
		_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, 4);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + 4));
			return TypedArray<Dictionary>();
		}

		size_t pkt_len = bytes_to_num_adv_itr<size_t>(p_rx_bfr.ptr(), 3, p_pkt_idx);
		_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, pkt_len);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + pkt_len));
			return TypedArray<Dictionary>();
		}

		uint8_t seq_num = p_rx_bfr[p_pkt_idx++];
		uint8_t header_byte = p_rx_bfr[p_pkt_idx++];  // 0x00 or 0xFE

		if (header_byte == 0xFE && pkt_len == 7) {
			p_pkt_idx += pkt_len;
			break;
		}

		const size_t nullmap_start = p_pkt_idx;
		p_pkt_idx += nullmap_bytes;	 // Advance past null bitmap
		Dictionary row;
		for (uint32_t c = 0; c < col_cnt; ++c) {
			int byte_i = (c + 2) >> 3;
			int bit_i = (c + 2) & 7;
			bool is_null = (p_rx_bfr[nullmap_start + byte_i] >> bit_i) & 1;

			const Dictionary& col_meta = p_col_defs[c];
			int type_code = int(col_meta["field_type"]);
			bool is_unsigned = int(col_meta["flags"]) & 32;
			String col_name = String(col_meta["name"]);
			Variant value;
			if (is_null) {
				value = Variant();
			} else {
				switch (MySqlFieldType(type_code)) {
					case MYSQL_TYPE_TINY:
						value = bytes_to_num_adv_itr<uint8_t>(p_rx_bfr.ptr(), 1, p_pkt_idx);
						break;
					case MYSQL_TYPE_SHORT:
					case MYSQL_TYPE_YEAR:
						value = bytes_to_num_adv_itr<uint16_t>(p_rx_bfr.ptr(), 2, p_pkt_idx);
						break;
					case MYSQL_TYPE_INT24:
						value = bytes_to_num_adv_itr<uint32_t>(p_rx_bfr.ptr(), 3, p_pkt_idx);
						break;
					case MYSQL_TYPE_LONG:
						value = bytes_to_num_adv_itr<uint32_t>(p_rx_bfr.ptr(), 4, p_pkt_idx);
						break;
					case MYSQL_TYPE_FLOAT: {
						float fval;
						memcpy(&fval, &p_rx_bfr[p_pkt_idx], sizeof(float));
						p_pkt_idx += sizeof(float);
						value = fval;
						break;
					}
					case MYSQL_TYPE_LONGLONG:
						value = bytes_to_num_adv_itr<uint64_t>(p_rx_bfr.ptr(), 8, p_pkt_idx);
						break;
					case MYSQL_TYPE_DOUBLE: {
						double dval;
						memcpy(&dval, &p_rx_bfr[p_pkt_idx], sizeof(double));
						if (_dbl_to_string) {
							value = vformat("%.9f", dval);
						} else {
							value = dval;
						}
						p_pkt_idx += sizeof(double);
						break;
					}
					case MYSQL_TYPE_DECIMAL:
					case MYSQL_TYPE_NEWDECIMAL:
					case MYSQL_TYPE_STRING:
					case MYSQL_TYPE_VAR_STRING: {
						uint64_t field_len = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
						if (field_len == UINT64_MAX) {
							value = "";	 // NULL string
						} else {
							String str_val;
							str_val.parse_utf8((const char*)p_rx_bfr.ptr() + p_pkt_idx, field_len);
							value = str_val;
							p_pkt_idx += field_len;
						}
						break;
					}
					case MYSQL_TYPE_TIMESTAMP:
					case MYSQL_TYPE_DATETIME: {
						uint8_t ts_len = p_rx_bfr[p_pkt_idx++];
						uint16_t year = bytes_to_num_adv_itr<uint16_t>(p_rx_bfr.ptr(), 2, p_pkt_idx);
						uint8_t month = p_rx_bfr[p_pkt_idx++];
						uint8_t day = p_rx_bfr[p_pkt_idx++];
						uint8_t hour = p_rx_bfr[p_pkt_idx++];
						uint8_t min = p_rx_bfr[p_pkt_idx++];
						uint8_t sec = p_rx_bfr[p_pkt_idx++];

						if (ts_len == 11) {
							uint32_t micro = bytes_to_num_adv_itr<uint32_t>(p_rx_bfr.ptr(), 4, p_pkt_idx);
							value = vformat(
									"%04d-%02d-%02d %02d:%02d:%02d.%06d", year, month, day, hour, min, sec, micro);
						} else {
							value = vformat("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec);
						}
					} break;
					default:
						break;
				}
			}

			row[col_name] = value;
		}
		rows.append(row);
	}

	return TypedArray<Dictionary>(rows);
}

TypedArray<Dictionary> MariaDBConnector::_parse_string_rows(PackedByteArray& p_rx_bfr,
															size_t& p_pkt_idx,
															const TypedArray<Dictionary>& p_col_defs,
															const bool p_dep_eof) {
	TypedArray<Dictionary> rows;
	int64_t col_cnt = p_col_defs.size();
	bool done = false;
	int bfr_size = 0;
	uint64_t len_encode = 0;
	// process values
	while (!done && p_pkt_idx < (size_t)p_rx_bfr.size()) {
		// Last packet (OK-Packet) is always 11 bytes, pkt len code = 3 bytes, seq = 1 byte, pkt
		// data = 7 bytes
		_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, 11);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + 11));
			return TypedArray<Dictionary>();
		}

		size_t pkt_len = bytes_to_num_adv_itr<size_t>(p_rx_bfr.ptr(), 3, p_pkt_idx);
		_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, pkt_len);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + pkt_len));
			return TypedArray<Dictionary>();
		}
		// uint8_t seq_num = srvr_response[p_pkt_idx++];
		p_pkt_idx++;

		uint8_t marker = p_rx_bfr[p_pkt_idx];

		if (marker == 0xFE && p_dep_eof && pkt_len < 0xFFFFFF) {
			done = true;
			break;
		}

		Dictionary dict;
		// https://mariadb.com/kb/en/protocol-data-types/#length-encoded-strings
		for (size_t col_idx = 0; col_idx < col_cnt; ++col_idx) {
			_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, 2);
			if (_last_error != OK) {
				ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + 2));
				return TypedArray<Dictionary>();
			}
			marker = p_rx_bfr[p_pkt_idx];
			if (marker == 0xFF) {
				p_pkt_idx++;
				// if (marker == 0xFF) // ERR_Packet
				//
				// if (arker == 0xFB) - LOCAL_INFILE Packet if the query was "LOCAL INFILE)
				// if ((marker == 0x00 && !dep_eof /* && pkt_len < 0xFFFFFF */) ||
				//  		(marker == 0xFE && pkt_len < 0xFFFFFF && dep_eof)) {
				//  	//OK_Packet
				//  	done = true;
				//  	break;
				//  }
			} else {
				if (marker == 0xFE) {
					// if (marker == 0xFE && pkt_len < 0xFFFFFF && !p_dep_eof){
					// EOF PACKET
					// is this possible in COM_QUERY??
					// }
					len_encode = 9;
				} else if (marker == 0xFD) {
					len_encode = 4;
				} else if (marker == 0xFC) {
					len_encode = 3;
				} else {
					len_encode = 1;
				}

				_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, len_encode);
				if (_last_error != OK) {
					ERR_PRINT(
							vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + len_encode));
					return TypedArray<Dictionary>();
				}
				if (marker == 0xFB) {
					len_encode = 0;
					p_pkt_idx++;
				} else {
					len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
					_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, len_encode);
				}

				if (_last_error != OK) {
					ERR_PRINT(
							vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + len_encode));
					return TypedArray<Dictionary>();
				}
				bool valid = false;

				// NOTE when accessing Dictionaries in C++ you must assign the value to
				// the expected type or you get undefined and erratic  behavior
				String field_name = String(p_col_defs[col_idx].get("name", &valid));
				int64_t charset = int64_t(p_col_defs[col_idx].get("char_set", &valid));

				ERR_FAIL_COND_V_EDMSG(
						!valid, TypedArray<Dictionary>(), vformat("ERROR: 'name' key is missing at index %d", col_idx));

				if (len_encode > 0) {
					PackedByteArray data = _get_pkt_bytes_adv_idx(p_rx_bfr, p_pkt_idx, len_encode);

					valid = false;
					int64_t field_type = int64_t(p_col_defs[col_idx].get("field_type", &valid));

					if (!valid) {
						dict[field_name] = Variant();  // Store empty if missing
					} else {
						dict[field_name] = _get_type_data(field_type, data, charset);
					}
				} else {
					dict[field_name] = Variant();
				}
			}
		}

		if (!done) rows.push_back(dict);
	}

	return rows;
}
MariaDBConnector::ErrorCode MariaDBConnector::_prepared_params_send(const uint32_t p_stmt_id,
																	const TypedArray<Dictionary>& p_params) {
	const int param_count = p_params.size();
	if (_prep_column_data.has(p_stmt_id)) {
		TypedArray<Dictionary> expected_cols = _prep_column_data[p_stmt_id];
		if (expected_cols.size() > 0 && param_count == 0) {
			ERR_PRINT("Expected parameter dictionary array, but received empty or invalid input.");
			return ErrorCode::ERR_INVALID_PARAMETER;
		}
	}
	PackedByteArray tx_buf;
	tx_buf.push_back(0x17);	 // COM_STMT_EXECUTE

	tx_buf.push_back((p_stmt_id >> 0) & 0xFF);	// Statement ID (4 bytes)
	tx_buf.push_back((p_stmt_id >> 8) & 0xFF);
	tx_buf.push_back((p_stmt_id >> 16) & 0xFF);
	tx_buf.push_back((p_stmt_id >> 24) & 0xFF);

	tx_buf.push_back(0x00);	 // flags
	tx_buf.push_back(0x01);	 // iteration count
	tx_buf.push_back(0x00);
	tx_buf.push_back(0x00);
	tx_buf.push_back(0x00);

	const int nullmap_size = (param_count + 7) / 8;
	if (param_count > 0) {
		Variant param_type = p_params[0];
		if (param_type.get_type() != Variant::DICTIONARY) return ErrorCode::ERR_INVALID_PARAMETER;

		const int nullmap_offset = tx_buf.size();

		for (int i = 0; i < nullmap_size; ++i) tx_buf.push_back(0x00);	// nullmap placeholder, filled below

		tx_buf.push_back(0x01);	 // new_params_bound_flag

		for (int i = 0; i < param_count; ++i) {
			Variant param_type = p_params[i];
			if (param_type.get_type() != Variant::DICTIONARY) return ErrorCode::ERR_INVALID_PARAMETER;

			Dictionary param = p_params[i];
			if (param.size() != 1) return ErrorCode::ERR_INVALID_PARAMETER;
			Variant v = param.values()[0];
			if (v.get_type() == Variant::NIL) {
				int byte_i = i >> 3;
				int bit_i = i & 7;
				tx_buf[nullmap_offset + byte_i] |= (1 << bit_i);
			}

			uint16_t k = param.keys()[0];
			switch (k) {
				case FT_TINYINT:
					tx_buf.push_back(MYSQL_TYPE_TINY);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_TINYINT_U:
					tx_buf.push_back(MYSQL_TYPE_TINY);
					tx_buf.push_back(SIGN_UNSIGNED);
					break;
				case FT_SHORT:
					tx_buf.push_back(MYSQL_TYPE_SHORT);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_SHORT_U:
					tx_buf.push_back(MYSQL_TYPE_SHORT);
					tx_buf.push_back(SIGN_UNSIGNED);
					break;
				case FT_INT:
					tx_buf.push_back(MYSQL_TYPE_LONG);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_INT_U:
					tx_buf.push_back(MYSQL_TYPE_LONG);
					tx_buf.push_back(SIGN_UNSIGNED);
					break;
				case FT_FLOAT:
					tx_buf.push_back(MYSQL_TYPE_FLOAT);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_DOUBLE:
					tx_buf.push_back(MYSQL_TYPE_DOUBLE);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_TIMESTAMP:
					tx_buf.push_back(MYSQL_TYPE_TIMESTAMP);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_BIGINT:
					tx_buf.push_back(MYSQL_TYPE_LONGLONG);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_BIGINT_U:
					tx_buf.push_back(MYSQL_TYPE_LONGLONG);
					tx_buf.push_back(SIGN_UNSIGNED);
					break;
				case FT_MEDIUMINT:
					tx_buf.push_back(MYSQL_TYPE_INT24);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_MEDIUMINT_U:
					tx_buf.push_back(MYSQL_TYPE_INT24);
					tx_buf.push_back(SIGN_UNSIGNED);
					break;
				case FT_DATE:
					tx_buf.push_back(MYSQL_TYPE_DATE);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_TIME:
					tx_buf.push_back(MYSQL_TYPE_TIME);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_DATETIME:
					tx_buf.push_back(MYSQL_TYPE_DATETIME);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_YEAR:
					tx_buf.push_back(MYSQL_TYPE_YEAR);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_NEWDATE:
					tx_buf.push_back(MYSQL_TYPE_NEWDATE);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_VARCHAR:
					tx_buf.push_back(MYSQL_TYPE_VARCHAR);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_BIT:
					tx_buf.push_back(MYSQL_TYPE_BIT);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_JSON:
					tx_buf.push_back(MYSQL_TYPE_JSON);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_DECIMAL:
					tx_buf.push_back(MYSQL_TYPE_NEWDECIMAL);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_ENUM:
					tx_buf.push_back(MYSQL_TYPE_ENUM);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_SET:
					tx_buf.push_back(MYSQL_TYPE_SET);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_TINYBLOB:
					tx_buf.push_back(MYSQL_TYPE_TINY_BLOB);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_MEDIUMBLOB:
					tx_buf.push_back(MYSQL_TYPE_MEDIUM_BLOB);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_LONGBLOB:
					tx_buf.push_back(MYSQL_TYPE_LONG_BLOB);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_BLOB:
					tx_buf.push_back(MYSQL_TYPE_BLOB);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_VAR_STRING:
					tx_buf.push_back(MYSQL_TYPE_VAR_STRING);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_STRING:
					tx_buf.push_back(MYSQL_TYPE_STRING);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				case FT_GEOMETRY:
					tx_buf.push_back(MYSQL_TYPE_GEOMETRY);
					tx_buf.push_back(SIGN_SIGNED);
					break;
				default:
					return ErrorCode::ERR_INVALID_PARAMETER;
			}
		}

		// Parameter values
		for (int i = 0; i < param_count; ++i) {
			Dictionary param = p_params[i];
			FieldType field_type = FieldType(uint8_t(param.keys()[0]));
			Variant value = param.values()[0];

			if (value.get_type() == Variant::NIL) {
				continue;
			}

			switch (field_type) {
				case FT_TINYINT:
				case FT_TINYINT_U:
					tx_buf.push_back(uint8_t(value));
					break;
				case FT_SHORT:
				case FT_SHORT_U: {
					uint16_t val = uint16_t(value);
					tx_buf.push_back(val & 0xFF);
					tx_buf.push_back((val >> 8) & 0xFF);
					break;
				}
				case FT_INT:
				case FT_INT_U:
				case FT_MEDIUMINT:
				case FT_MEDIUMINT_U: {
					uint32_t val = uint32_t(value);
					tx_buf.push_back(val & 0xFF);
					tx_buf.push_back((val >> 8) & 0xFF);
					tx_buf.push_back((val >> 16) & 0xFF);
					tx_buf.push_back((val >> 24) & 0xFF);
					break;
				}
				case FT_BIGINT:
				case FT_BIGINT_U: {
					uint64_t val = uint64_t(value);
					for (int b = 0; b < 8; ++b) tx_buf.push_back((val >> (b * 8)) & 0xFF);
					break;
				}
				case FT_FLOAT: {
					float f = value;
					const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&f);
					for (int b = 0; b < 4; ++b) tx_buf.push_back(ptr[b]);
					break;
				}
				case FT_DOUBLE: {
					double d = value;
					const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&d);
					for (int b = 0; b < 8; ++b) tx_buf.push_back(ptr[b]);
					break;
				}
				case FT_VAR_STRING:
				case FT_VARCHAR:
				case FT_STRING:
				case FT_DECIMAL:
				case FT_JSON:
				case FT_ENUM:
				case FT_SET: {
					PackedByteArray str_buf = value.operator String().to_utf8_buffer();
					uint64_t len = str_buf.size();
					if (len < 251) {
						tx_buf.push_back(uint8_t(len));
					} else {
						tx_buf.push_back(0xFC);
						tx_buf.push_back(len & 0xFF);
						tx_buf.push_back((len >> 8) & 0xFF);
					}
					tx_buf.append_array(str_buf);
					break;
				}
				default:
					return ErrorCode::ERR_PREPARE_FAILED;
			}
		}
	}

	_add_packet_header(tx_buf, 0);
	return (ErrorCode)_stream->put_data(tx_buf);
}

Variant MariaDBConnector::_query(const String& p_sql_stmt, const bool p_is_command) {
	_last_error = ErrorCode::OK;
	if (!is_connected_db()) {
		_last_error = ErrorCode::ERR_NOT_CONNECTED;
		if (p_is_command) {
			return 0;
		} else {
			return ERR_NOT_CONNECTED;
		}
	}
	if (!_authenticated) {
		_last_error = ErrorCode::ERR_NOT_CONNECTED;
		if (p_is_command) {
			return 0;
		} else {
			return (uint32_t)ErrorCode::ERR_AUTH_FAILED;
		}
	}

	PackedByteArray tx_bfr;

	tx_bfr.push_back(0x03);	 // COM_QUERY
	_last_query_converted = p_sql_stmt.to_utf8_buffer();

	tx_bfr.append_array(_last_query_converted);
	_add_packet_header(tx_bfr, 0);

	_last_transmitted = tx_bfr;
	_stream_mutex->lock();
	_last_error = (ErrorCode)_stream->put_data(tx_bfr);
	if (_last_error != OK) return _last_error;

	Variant res = _com_query_response(p_is_command);
	_stream_mutex->unlock();
	return res;
}

MariaDBConnector::ErrorCode MariaDBConnector::_rcv_bfr_chk(PackedByteArray& p_bfr,
														   int& p_bfr_size,
														   const size_t p_cur_pos,
														   const size_t p_bytes_needed) {
	p_bfr_size = p_bfr.size();
	if (p_bfr_size - p_cur_pos < p_bytes_needed) p_bfr.append_array(_read_buffer(_server_timout_msec));

	p_bfr_size = p_bfr.size();
	if (p_bfr_size - p_cur_pos < p_bytes_needed) {
		return MariaDBConnector::ErrorCode::ERR_PACKET_LENGTH_MISMATCH;
	} else {
		return MariaDBConnector::ErrorCode::OK;
	}
}

PackedByteArray MariaDBConnector::_read_buffer(uint32_t p_timeout, uint32_t p_expected_bytes) {
	int32_t byte_cnt = 0;
	PackedByteArray out_buffer;
	uint64_t start_msec = Time::get_singleton()->get_ticks_msec();
	uint64_t time_lapse = 0;
	bool data_rcvd = false;
	while (is_connected_db() && time_lapse < p_timeout) {
		_last_error = (ErrorCode)_stream->poll();
		if (_last_error != OK) return PackedByteArray();

		byte_cnt = _stream->get_available_bytes();
		if (byte_cnt > 0) {
			out_buffer.append_array(_stream->get_data(byte_cnt)[1]);
			data_rcvd = (p_expected_bytes == 0 || out_buffer.size() >= p_expected_bytes);
		} else if (data_rcvd) {
			break;
		}
		time_lapse = Time::get_singleton()->get_ticks_msec() - start_msec;
	}

	return out_buffer;
}

TypedArray<Dictionary> MariaDBConnector::_read_columns_data(PackedByteArray& p_rx_bfr,
															size_t& p_pkt_idx,
															const uint16_t p_col_cnt) {
	int bfr_size = 0;
	uint64_t len_encode = 0;
	TypedArray<Dictionary> col_data;

	//	for each column (i.e column_count times)
	for (size_t col_idx = 0; col_idx < p_col_cnt; ++col_idx) {
		_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, 24);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + 24));
			return TypedArray<Dictionary>();
		}

		size_t pkt_len = bytes_to_num_adv_itr<size_t>(p_rx_bfr.ptr(), 3, p_pkt_idx);
		_last_error = _rcv_bfr_chk(p_rx_bfr, bfr_size, p_pkt_idx, pkt_len);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, p_pkt_idx + pkt_len));
			return TypedArray<Dictionary>();
		}
		// uint8_t seq_num = p_srvr_response[p_pkt_idx++];
		p_pkt_idx++;

		//	Column Definition packet
		// https://mariadb.com/kb/en/result-set-packets/#column-definition-packet
		//	string<lenenc> catalog (always 'def')
		len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
		String s = vbytes_to_utf8_adv_itr(p_rx_bfr, p_pkt_idx, len_encode);

		//	string<lenenc> schema (database name)
		len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
		vbytes_to_utf8_adv_itr(p_rx_bfr, p_pkt_idx, len_encode);

		//	string<lenenc> table alias
		len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
		vbytes_to_utf8_adv_itr(p_rx_bfr, p_pkt_idx, len_encode);

		//	string<lenenc> table
		len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
		vbytes_to_utf8_adv_itr(p_rx_bfr, p_pkt_idx, len_encode);

		//	string<lenenc> column alias
		len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
		String column_name = vbytes_to_utf8_adv_itr(p_rx_bfr, p_pkt_idx, len_encode);

		//	string<lenenc> column
		len_encode = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);
		vbytes_to_utf8_adv_itr(p_rx_bfr, p_pkt_idx, len_encode);

		// TODO(sigrudds1) Handle "MariaDBConnector extended capablities" (several
		// locations)
		//		if extended type supported (see
		// MARIADB_CLIENT_EXTENDED_TYPE_INFO ) 			int<lenenc>
		// length extended info 			loop
		// int<1> data type: 0x00:type, 0x01: format string<lenenc> value

		//	int<lenenc> length of fixed fields (=0x0C)
		uint64_t remaining = _decode_lenenc_adv_itr(p_rx_bfr, p_pkt_idx);

		//	int<2> character set number
		uint16_t char_set = bytes_to_num_adv_itr<uint16_t>(p_rx_bfr.ptr(), 2, p_pkt_idx);

		// int<4> max. column size the number in parenthesis eg int(10),
		// varchar(255) uint32_t col_size =
		uint32_t col_len = bytes_to_num_adv_itr<uint32_t>(p_rx_bfr.ptr(), 4, p_pkt_idx);

		//	int<1> Field types
		// https://mariadb.com/kb/en/result-set-packets/#field-types
		uint8_t field_type = p_rx_bfr[p_pkt_idx++];

		//	int<2> Field detail flag
		// https://mariadb.com/kb/en/result-set-packets/#field-details-flag
		uint16_t flags = bytes_to_num_adv_itr<uint16_t>(p_rx_bfr.ptr(), 2, p_pkt_idx);

		//	int<1> decimals
		uint8_t decimals = p_rx_bfr[p_pkt_idx++];

		//	int<2> - unused -
		p_pkt_idx += 2;

		Dictionary column_data;
		column_data["name"] = column_name;
		column_data["char_set"] = char_set;
		column_data["length"] = col_len;
		column_data["field_type"] = field_type;
		column_data["flags"] = flags;
		column_data["decimals"] = decimals;

		col_data.push_back(column_data);
	}
	return col_data;
}

MariaDBConnector::ErrorCode MariaDBConnector::_server_init_handshake_v10(const PackedByteArray& p_src_buffer) {
	// nul string - read the 5th byte until the first nul(00), this is server
	// version string, it is nul terminated
	size_t pkt_idx = 4;
	const uint8_t* buf_ptr = p_src_buffer.ptr();
	const size_t buf_size = p_src_buffer.size();

	size_t str_len = 0;
	while (pkt_idx + str_len < buf_size && buf_ptr[pkt_idx + str_len] != 0) {
		str_len++;
	}

	_server_ver_str.parse_utf8((const char*)(buf_ptr + pkt_idx), str_len);
	_server_ver_str = _server_ver_str.strip_edges();

	if (_server_ver_str.begins_with("5.5.5-")) {
		PackedStringArray split_ver_str = _server_ver_str.split("-");
		PackedStringArray split_ver_str_seg = split_ver_str[1].split(".");

		_srvr_major_ver = split_ver_str_seg[0].to_int();
		_srvr_minor_ver = split_ver_str_seg[1].to_int();
	}

	pkt_idx += str_len + 1;
	// 4bytes - doesn't appear to be needed.
	pkt_idx += 4;

	// salt part 1 - 8 bytes
	PackedByteArray server_salt = _get_pkt_bytes_adv_idx(p_src_buffer, pkt_idx, 8);

	// reserved byte
	pkt_idx++;

	// 2bytes -server capabilities part 1
	_server_capabilities = (uint64_t)p_src_buffer[pkt_idx++];
	_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 8;

	// 1byte - server default collation code
	pkt_idx++;

	// 2bytes - Status flags
	// uint16_t status = 0;
	// status = (uint16_t)p_src_buffer[pkt_idx++;
	// status += ((uint16_t)p_src_buffer[pkt_idx++]) << 8;
	pkt_idx += 2;

	// 2bytes - server capabilities part 2
	_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 16;
	_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 24;

	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_PROTOCOL_41)) {
		ERR_FAIL_V_MSG(ErrorCode::ERR_AUTH_PROTOCOL_MISMATCH, "Incompatible authorization protocol!");
	}
	// TODO(sigrudds1) Make auth plugin not required if using ssl/tls
	if (!(_server_capabilities & (uint64_t)Capabilities::PLUGIN_AUTH)) {
		ERR_FAIL_V_MSG(ErrorCode::ERR_AUTH_PROTOCOL_MISMATCH, "Authorization protocol not set!");
	}

	// 1byte - salt length 0 for none
	uint8_t server_salt_length = p_src_buffer[pkt_idx++];

	// 6bytes - filler
	pkt_idx += 6;

	// 4bytes - filler or server capabilities part 3 (mariadb v10.2 or later)
	// "MariaDBConnector extended capablities"
	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) && _srvr_major_ver >= 10 &&
		_srvr_minor_ver >= 2) {
		_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 32;
		_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 40;
		_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 48;
		_server_capabilities += ((uint64_t)p_src_buffer[pkt_idx++]) << 56;
	} else {
		pkt_idx += 4;
	}

	// 12bytes - salt part 2
	for (size_t j = 0; j < (size_t)std::max(13, server_salt_length - 8); j++)
		server_salt.push_back(p_src_buffer[pkt_idx++]);

	// 1byte - reserved
	// nul string - auth plugin name, length = auth plugin string length
	String tmp;
	while (p_src_buffer[++pkt_idx] != 0 && pkt_idx < (size_t)p_src_buffer.size()) {
		tmp += p_src_buffer[pkt_idx];
	}

	// determine which auth method the server can use
	AuthType p_srvr_auth_type = _get_server_auth_type(tmp);

	return _client_protocol_v41(p_srvr_auth_type, server_salt);
}  // server_init_handshake_v10

void MariaDBConnector::_hash_password(String p_password) {
	// Store password as a hash, only the hash is needed
	if (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE) {
		_password_hashed = p_password.sha1_buffer();
	} else if (_client_auth_type == AUTH_TYPE_ED25519) {
		_password_hashed.resize(64);

		mbedtls_sha512_context ctx;
		mbedtls_sha512_init(&ctx);
		mbedtls_sha512_starts(&ctx, 0);
		mbedtls_sha512_update(&ctx, reinterpret_cast<const uint8_t*>(p_password.utf8().ptr()), p_password.length());
		mbedtls_sha512_finish(&ctx, _password_hashed.ptrw());
		mbedtls_sha512_free(&ctx);
	}
}

void MariaDBConnector::_update_username(String p_username) { _username = p_username.to_utf8_buffer(); }

// public
MariaDBConnector::ErrorCode MariaDBConnector::connect_db(const String& p_host,
														 const int p_port,
														 const String& p_dbname,
														 const String& p_username,
														 const String& p_password,
														 const AuthType p_authtype,
														 const bool p_is_prehashed) {
	if (p_host.is_valid_ip_address()) {
		_ip = p_host;
	} else {
		_ip = IP::get_singleton()->resolve_hostname(p_host, (IP::Type)_ip_type);
	}

	if (!_ip.is_valid_ip_address()) {
		ERR_PRINT("Invalid hostname or IP address");
		return ErrorCode::ERR_INVALID_HOSTNAME;
	}

	if (p_port <= 0 || p_port > 65535) {
		ERR_PRINT("Invalid port");
		return ErrorCode::ERR_INVALID_PORT;
	}
	_port = p_port;

	if (p_dbname.length() <= 0 && _client_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB) {
		ERR_PRINT("dbname not set");
		return ErrorCode::ERR_DB_NAME_EMPTY;
	} else {
		set_db_name(p_dbname);
	}

	if (p_username.length() <= 0) {
		ERR_PRINT("username not set");
		return ErrorCode::ERR_USERNAME_EMPTY;
	}

	if (p_password.length() <= 0) {
		ERR_PRINT("password not set");
		return ErrorCode::ERR_PASSWORD_EMPTY;
	}

	if (p_is_prehashed) {
		if (p_authtype == AUTH_TYPE_MYSQL_NATIVE) {
			if (!is_valid_hex(p_password, 40)) {
				ERR_PRINT(
						"Password not proper for MySQL Native prehash, must be 40 "
						"hex characters!");
				return ErrorCode::ERR_PASSWORD_HASH_LENGTH;
			}
		} else if (p_authtype == AUTH_TYPE_ED25519) {
			if (!is_valid_hex(p_password, 128)) {
				ERR_PRINT("Password not proper for ED25519, must be 128 hex characters!");
				return ErrorCode::ERR_PASSWORD_HASH_LENGTH;
			}
		}

		_password_hashed = p_password.hex_decode();

	} else {
		_hash_password(p_password);
	}

	_update_username(p_username);

	_client_auth_type = p_authtype;
	return _connect();
}

MariaDBConnector::ErrorCode MariaDBConnector::connect_db_ctx(const Ref<MariaDBConnectContext>& p_context) {
	if (p_context.is_null()) {
		ERR_PRINT("ConnectionContext is null.");
		return ErrorCode::ERR_INIT_ERROR;
	}

	const int encoding = p_context->get_encoding();
	String password = p_context->get_password();
	const bool is_prehashed = p_context->get_is_prehashed();

	if (encoding == MariaDBConnectContext::ENCODE_BASE64) {
		// BASE64 should always be treated as binary -> hex
		password = Marshalls::get_singleton()->base64_to_raw(password).hex_encode();
	} else if (is_prehashed) {
		if (encoding == MariaDBConnectContext::ENCODE_PLAIN) {
			// convert plain to hex
			password = password.to_utf8_buffer().hex_encode();
		}
		// Just pass hex
	}
	// hex decode is dangerous, just pass the unmodified string if hex or plain

	return connect_db(p_context->get_hostname(),
					  p_context->get_port(),
					  p_context->get_db_name(),
					  p_context->get_username(),
					  password,
					  static_cast<MariaDBConnector::AuthType>(p_context->get_auth_type()),
					  is_prehashed);
}

Ref<MariaDBConnector> MariaDBConnector::connection_instance(const Ref<MariaDBConnectContext>& p_context) {
	ERR_FAIL_COND_V_EDMSG(p_context.is_null(), Ref<MariaDBConnector>(), "ConnectionContext is null.");

	const int encoding = p_context->get_encoding();
	String password = p_context->get_password();
	const bool is_prehashed = p_context->get_is_prehashed();

	if (encoding == MariaDBConnectContext::ENCODE_BASE64) {
		PackedByteArray raw = Marshalls::get_singleton()->base64_to_raw(password);
		password = raw.hex_encode();
	} else if (is_prehashed && encoding == MariaDBConnectContext::ENCODE_PLAIN) {
		PackedByteArray raw = password.to_utf8_buffer();
		password = raw.hex_encode();
	}

	Ref<MariaDBConnector> conn;
	conn.instantiate();

	ErrorCode err = conn->connect_db(p_context->get_hostname(),
									 p_context->get_port(),
									 p_context->get_db_name(),
									 p_context->get_username(),
									 password,
									 static_cast<AuthType>(p_context->get_auth_type()),
									 is_prehashed);

	ERR_FAIL_COND_V_EDMSG(
			err != ErrorCode::OK, Ref<MariaDBConnector>(), vformat("Failed to connect: error code %d", int(err)));

	return conn;
}

void MariaDBConnector::disconnect_db() {
	// _tcp_polling = false;
	_stream_mutex->lock();
	if (is_connected_db()) {
		// say goodbye too the server
		// uint8_t output[5] = {0x01, 0x00, 0x00, 0x00, 0x01};
		// String str = "0100000001";
		// _stream->put_data(str.hex_decode());
		_last_error = (ErrorCode)_stream->put_data(PackedByteArray({ 0x01, 0x00, 0x00, 0x00, 0x01 }));
		_stream->disconnect_from_host();
	}
	_authenticated = false;
	_stream_mutex->unlock();
}

Dictionary MariaDBConnector::excecute_command(const String& p_sql_stmt) { return _query(p_sql_stmt, true); }

PackedByteArray MariaDBConnector::get_last_query_converted() { return _last_query_converted; }

PackedByteArray MariaDBConnector::get_last_response() { return _last_response; }

PackedByteArray MariaDBConnector::get_last_transmitted() { return _last_transmitted; }

PackedByteArray MariaDBConnector::get_client_ed25519_signature(const PackedByteArray& p_sha512_hashed_passwd,
															   const PackedByteArray& p_svr_msg) {
	// MySQL does not supprt this auth method
	PackedByteArray rtn_val;
	rtn_val.resize(64);
	ed25519_sign_msg(p_sha512_hashed_passwd.ptr(), p_svr_msg.ptr(), 32, rtn_val.ptrw());
	return rtn_val;
}

PackedByteArray MariaDBConnector::get_mysql_native_password_hash(const PackedByteArray& p_sha1_hashed_passwd,
																 const PackedByteArray& p_srvr_salt) {
	// Per https://mariadb.com/kb/en/connection/#mysql_native_password-plugin
	// Both MariaDB and MySQL support this authentication method

	// First SHA1 Hashing
	PackedByteArray hash = _sha1(p_sha1_hashed_passwd);
	// Combine server salt and hash
	PackedByteArray combined_salt_pwd;
	combined_salt_pwd.resize(40);  // 20-byte salt + 20-byte hash

	for (int i = 0; i < 20; i++) {
		combined_salt_pwd.set(i, p_srvr_salt[i]);  // First 20 bytes: salt
		combined_salt_pwd.set(i + 20, hash[i]);	 // Next 20 bytes: hashed password
	}

	// Second SHA1 Hashing
	PackedByteArray final_hash = _sha1(combined_salt_pwd);
	// XOR original password hash with final hash
	PackedByteArray hash_out;
	hash_out.resize(20);

	for (int i = 0; i < 20; i++) {
		hash_out.set(i, p_sha1_hashed_passwd[i] ^ final_hash[i]);
	}

	return hash_out;
}

bool MariaDBConnector::is_connected_db() {
	_last_error = (ErrorCode)_stream->poll();
	return _stream->get_status() == StreamPeerTCP::STATUS_CONNECTED;
}

void MariaDBConnector::ping_srvr() {
	_stream_mutex->lock();
	if (is_connected_db()) _stream->put_data(PackedByteArray({ 0x01, 0x00, 0x00, 0x00, 0x0E }));
	PackedByteArray ret = _read_buffer(1000, 12);
	_stream_mutex->unlock();
}

Dictionary MariaDBConnector::prepared_statement(const String& p_sql) {
	_last_error = ErrorCode::OK;

	PackedByteArray send_buffer_vec;
	send_buffer_vec.push_back(0x16);  // COM_STMT_PREPARE code (0x16)
	send_buffer_vec.append_array(p_sql.to_utf8_buffer());
	_add_packet_header(send_buffer_vec, 0);
	_last_transmitted = send_buffer_vec;

	_stream_mutex->lock();
	_last_error = (ErrorCode)_stream->put_data(send_buffer_vec);
	if (_last_error != OK) return Dictionary();
	PackedByteArray rx_bfr = _read_buffer(_server_timout_msec);
	if (rx_bfr.is_empty()) {
		_last_error = ErrorCode::ERR_NO_RESPONSE;
		_stream_mutex->unlock();
		return Dictionary();
	}

	size_t pkt_idx = 0;
	size_t pkt_len = bytes_to_num_adv_itr<size_t>(rx_bfr.ptr(), 3, pkt_idx);
	int bfr_size = 0;
	_last_error = _rcv_bfr_chk(rx_bfr, bfr_size, pkt_idx, pkt_len);
	if (_last_error != OK) {
		ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_idx + pkt_len));
		_stream_mutex->unlock();
		return Dictionary();
	}
	uint8_t seq_num = rx_bfr[pkt_idx++];
	uint8_t status = rx_bfr[pkt_idx++];

	if (status != 0) {
		_last_error = ErrorCode::ERR_PREPARE_FAILED;
		_handle_server_error(rx_bfr, pkt_idx);
		_stream_mutex->unlock();
		return Dictionary();
	}

	uint32_t statement_id = bytes_to_num_adv_itr<uint32_t>(rx_bfr.ptr(), 4, pkt_idx);
	uint16_t num_columns = bytes_to_num_adv_itr<uint16_t>(rx_bfr.ptr(), 2, pkt_idx);
	uint16_t num_params = bytes_to_num_adv_itr<uint16_t>(rx_bfr.ptr(), 2, pkt_idx);

	pkt_idx += 3;

	Dictionary info;
	info["statement_id"] = statement_id;
	info["num_columns"] = num_columns;
	info["num_params"] = num_params;

	TypedArray<Dictionary> col_data;
	for (size_t p = 0; p < num_params; ++p) {
		// process parameter def packet
		pkt_len = bytes_to_num_adv_itr<size_t>(rx_bfr.ptr(), 3, pkt_idx);
		_last_error = _rcv_bfr_chk(rx_bfr, bfr_size, pkt_idx, pkt_len);
		if (_last_error != OK) {
			ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_idx + pkt_len));
			return Dictionary();
		}
		seq_num = rx_bfr[pkt_idx++];
		pkt_idx += pkt_len;
	}

	col_data = _read_columns_data(rx_bfr, pkt_idx, num_columns);
	_stream_mutex->unlock();
	_prep_column_data[statement_id] = col_data;

	return info;
}

TypedArray<Dictionary> MariaDBConnector::prepared_stmt_exec_select(uint32_t p_stmt_id,
																   const TypedArray<Dictionary>& p_params) {
	// TypedArray<Dictionary> MariaDBConnector::exec_prepped_select(uint32_t p_stmt_id, const Array &p_params) {
	// _last_error = _prepared_select_params_send(p_stmt_id, p_params);
	_stream_mutex->lock();
	_last_error = _prepared_params_send(p_stmt_id, p_params);
	if (_last_error != OK) {
		return TypedArray<Dictionary>();
	}

	PackedByteArray rx_bfr = _read_buffer(_server_timout_msec);
	if (rx_bfr.is_empty()) {
		_last_error = ErrorCode::ERR_NO_RESPONSE;
		_stream_mutex->unlock();
		return TypedArray<Dictionary>();
	}

	size_t pkt_idx = 0;
	size_t pkt_len = bytes_to_num_adv_itr<size_t>(rx_bfr.ptr(), 3, pkt_idx);
	int bfr_size = 0;
	_last_error = _rcv_bfr_chk(rx_bfr, bfr_size, pkt_idx, pkt_len);
	if (_last_error != OK) {
		_stream_mutex->unlock();
		ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_idx + pkt_len));
		return TypedArray<Dictionary>();
	}
	size_t seq_num = rx_bfr[pkt_idx++];

	uint8_t status = rx_bfr[pkt_idx];
	if (status == 0xFF) {
		_handle_server_error(rx_bfr, ++pkt_idx);
		_last_error = ERR_PREPARE_FAILED;
		_stream_mutex->unlock();
		return TypedArray<Dictionary>();
	}

	pkt_idx += 2;  // Skip over column count and status byte

	TypedArray<Dictionary> col_data = _prep_column_data.get(p_stmt_id, TypedArray<Dictionary>());
	if (col_data.size() == 0) {
		uint8_t marker = rx_bfr[pkt_idx++];
		if (marker == 0xFF) {
			// Proper error marker
			_last_error = ERR_UNAVAILABLE;
			ERR_PRINT("exec_prepped_select failed: ERR packet received");
		} else {
			_last_error = ERR_UNAVAILABLE;
			ERR_PRINT(vformat("exec_prepped_select unexpected marker: 0x%02X", marker));
		}
		_stream_mutex->unlock();
		return TypedArray<Dictionary>();
	}

	bool dep_eof = (_client_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);

	Variant rows = _parse_prepared_exec(rx_bfr, pkt_idx, col_data, dep_eof);
	if (rows.get_type() != Variant::ARRAY) {
		_last_error = ERR_UNAVAILABLE;
		_stream_mutex->unlock();
		return TypedArray<Dictionary>();
	}

	_stream_mutex->unlock();
	return TypedArray<Dictionary>(rows);
}

Dictionary MariaDBConnector::prepared_stmt_exec_cmd(uint32_t p_stmt_id, const TypedArray<Dictionary>& p_params) {
	_stream_mutex->lock();

	_last_error = _prepared_params_send(p_stmt_id, p_params);
	if (_last_error != OK) {
		_stream_mutex->unlock();
		return Dictionary();
	}
	PackedByteArray rx_bfr = _read_buffer(_server_timout_msec);
	if (rx_bfr.is_empty()) {
		_last_error = ErrorCode::ERR_NO_RESPONSE;
		_stream_mutex->unlock();
		return Dictionary();
	}

	size_t pkt_idx = 0;
	size_t pkt_len = bytes_to_num_adv_itr<size_t>(rx_bfr.ptr(), 3, pkt_idx);
	int bfr_size = 0;
	_last_error = _rcv_bfr_chk(rx_bfr, bfr_size, pkt_idx, pkt_len);
	if (_last_error != OK) {
		_stream_mutex->unlock();
		ERR_PRINT(vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_idx + pkt_len));
		return Dictionary();
	}

	pkt_idx++;

	uint8_t header = rx_bfr.decode_u8(pkt_idx++);
	if (header == 0xFF) {
		// ERR Packet
		_handle_server_error(rx_bfr, pkt_idx);
		_last_error = ErrorCode::ERR_EXECUTE_FAILED;
		_stream_mutex->unlock();
		return Dictionary();
	} else if (header == 0x00) {
		// OK Packet
		uint64_t affected_rows = _decode_lenenc_adv_itr(rx_bfr, pkt_idx);
		uint64_t last_insert_id = _decode_lenenc_adv_itr(rx_bfr, pkt_idx);
		uint16_t status_flags = bytes_to_num_adv_itr<uint16_t>(rx_bfr.ptr(), 2, pkt_idx);
		uint16_t warnings = bytes_to_num_adv_itr<uint16_t>(rx_bfr.ptr(), 2, pkt_idx);

		String info;
		if (pkt_idx < rx_bfr.size()) {
			info = String::utf8((const char*)&rx_bfr[pkt_idx], rx_bfr.size() - pkt_idx);
		}

		Dictionary result;
		result["affected_rows"] = affected_rows;
		result["last_insert_id"] = last_insert_id;
		result["status_flags"] = status_flags;
		result["warnings"] = warnings;
		result["info"] = info;
		_stream_mutex->unlock();
		return result;
	} else {
		// Possibly a result set packet — not handled in this path
		_last_error = (ErrorCode)ERR_PARSE_ERROR;
		_stream_mutex->unlock();
		ERR_PRINT("Unexpected header byte: " + itos(header));
		return Dictionary();
	}
}

MariaDBConnector::ErrorCode MariaDBConnector::prepared_statement_close(uint32_t stmt_id) {
	PackedByteArray tx_bfr;
	tx_bfr.resize(5);
	tx_bfr[0] = 0x19;  // COM_STMT_CLOSE
	tx_bfr.encode_u32(1, stmt_id);
	_add_packet_header(tx_bfr, 0);
	_stream_mutex->lock();
	_last_error = (ErrorCode)_stream->put_data(tx_bfr);
	_stream_mutex->unlock();
	return _last_error;
}

TypedArray<Dictionary> MariaDBConnector::select_query(const String& p_sql_stmt) {
	TypedArray<Dictionary> result;
	Variant query_result = _query(p_sql_stmt);

	if (query_result.get_type() == Variant::INT) {
		// Not a valid SELECT response, INSERT, DELETE, UPDATE or error
		return result;
	}

	Array raw_array = query_result;
	for (int i = 0; i < raw_array.size(); i++) {
		if (raw_array[i].get_type() == Variant::DICTIONARY) {
			result.push_back(raw_array[i]);
		}
	}

	return result;
}

void MariaDBConnector::set_dbl_to_string(bool p_is_to_str) { _dbl_to_string = p_is_to_str; }

// TODO If db is not the same and connected then change db on server
void MariaDBConnector::set_db_name(String p_dbname) {
	_dbname = p_dbname.to_utf8_buffer();
	// _dbname = p_dbname.to_ascii_buffer(); // TODO Add character set
	// compatibility??
}

void MariaDBConnector::set_ip_type(IpType p_type) { _ip_type = p_type; }
