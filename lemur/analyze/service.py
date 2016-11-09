"""
.. module: lemur.analyze.service
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
# import struct
# import requests
#
# from flask import current_app
#
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import load_der_public_key
#
#
# HEADERS = {'contentType': 'application/json'}
#
#
# def unpack_tls_array(packed_data, length_len):
#     """"""
#     padded_length = ["\x00"] * 8
#     padded_length[-length_len:] = packed_data[:length_len]
#     (length,) = struct.unpack(">Q", "".join(padded_length))
#     unpacked_data = packed_data[length_len:length_len+length]
#
#     if not len(unpacked_data) == length:
#         raise Exception("Data is only {0} bytes long, but length is {1} bytes".format(
#             len(unpacked_data), length
#         ))
#
#     rest_data = packed_data[length_len+length:]
#     return unpacked_data, rest_data
#
#
# def decode_signature(signature):
#     """Unpacks a given log signature."""
#     hash_alg, signature_alg = struct.unpack(">bb", signature[0:2])
#     unpacked_signature, rest = unpack_tls_array(signature[2:], 2)
#     assert rest == ""
#     return hash_alg, signature_alg, unpacked_signature
#
#
# def check_signature(signature, data, public_key):
#     """Determines if given signature is valid."""
#     hash_alg, signature_alg, unpacked_signature = decode_signature(signature)
#
#     if hash_alg != 4:
#         raise Exception("Hash algorithm is {0}, expected 4 (sha256)".format(hash_alg))
#
#     if signature_alg != 3:
#         raise Exception("Signature algorithm is {0}, expected 3 (ecdsa)".format(signature_alg))
#
#     public_key = load_der_public_key(public_key, backend=default_backend())
#     public_key.verify(
#         unpacked_signature,
#         data,
#         hashes.SHA256()
#     )
#
#
# def get_signed_tree_head(base_url):
#     """Retrieves the signed tree head signature for a given log."""
#     response = requests.get(base_url + 'ct/v1/get-sth')
#
#     if response != 200:
#         raise Exception("Unable to fetch the signed tree head for log: {0}".format(base_url))
#
#     return response.json()
#
#
# def tree_changed(old_signed_tree_head, new_signed_tree_head):
#     """Attempt to determine if the tree has changed, if so determine if it was changed correctly."""
#     if old_signed_tree_head['tree_size'] != new_signed_tree_head['tree_size']:
#         return True
#
#     current_app.logger.info("Tree size has not changed.")
#
#     if old_signed_tree_head['sha256_root_hash'] != new_signed_tree_head['sha256_root_hash']:
#         raise Exception(
#             "Root hashes do not match even though tree size has not changed. This violates the append-only property."
#         )
#
#
# def get_certificate_entries(base_url, start, end):
#     """Retrieve paginated list of entries from the log."""
#     response = requests.get(base_url + 'ct/v1/get-entries', params={'start': start, 'end': end}, headers=HEADERS)
#
#     if response.status_code != 200:
#         raise Exception("Unable to get all certificate entries from log: {0}".format(base_url))
#
#     return response.json()
#
#
# def extract_entry_data(entry):
#     """Extracts entry data."""
#     leaf_input = base64.decodestring(entry["leaf_input"])
#     (leaf_cert, timestamp, issuer_key_hash) = unpack_mtl(leaf_input)
#     extra_data = base64.decodestring(entry["extra_data"])
#     if issuer_key_hash != None:
#         (precert, extra_data) = extract_precertificate(extra_data)
#         leaf_cert = precert
#     certchain = decode_certificate_chain(extra_data)
#     return ([leaf_cert] + certchain, timestamp, issuer_key_hash)
#
#
# def get_certificates_from_log(base_url, num_certs, tree_size):
#     """Retrieve certificates from log file, handles the pagination of logs."""
#     fetched_entries = 0
#     end = tree_size + 1
#     while fetched_entries < end:
#         current_app.logger.debug("Fetching certificates from log: {0}".format(base_url))
#         entries = get_certificate_entries(base_url, fetched_entries, end)
#
#         if not entries:
#             break
#
#         for entry in entries:
#             fetched_entries += 1
#             yield entry
#
#
# def check_lock_signature(signed_tree_head, public_key):
#     """Determines if a downloaded logs signature is valid."""
#     signature = base64.decodestring(sth["tree_head_signature"])
#
#     version = struct.pack(">b", 0)
#     signature_type = struct.pack(">b", 1)
#     timestamp = struct.pack(">Q", sth["timestamp"])
#     tree_size = struct.pack(">Q", sth["tree_size"])
#     hash = base64.decodestring(sth["sha256_root_hash"])
#     tree_head = version + signature_type + timestamp + tree_size + hash
#
#     check_signature(baseurl, signature, tree_head, publickey=publickey)
#
#
# def create_violation_notification(certificate):
#     """Create a notification to be send to relevant parties."""
#     pass
#
#
# def fetch_transparency_keys(providers=None):
#     """Fetch the keys of the log servers you wish to query."""
#     response = requests.get("https://www.certificate-transparency.org/known-logs/all_logs_list.json?attredirects=0&d=1")
#
#     if response.status_code != 200:
#         raise Exception('Unable to fetch certificate transparency keys.')
#
#     return response.json()['logs']
#
#
# def download_log(log_url, public_key):
#     """Download individual log for processing."""
#
#     pass
#
#
# def find_relevant_certificates(domains):
#     """Searches a log for domains that we care about."""
#     pass
#
#
# def issued_by_lemur(certificate):
#     """Determine if given certificate was issued through Lemur."""
#     pass
#
#
# def audit_transparency_logs():
#     """Fetch transparency logs and attempt to determine if any covered domains
#        were issued outside of Lemur. If so, attempt to alert relevant parties.
#     """
#     pass
