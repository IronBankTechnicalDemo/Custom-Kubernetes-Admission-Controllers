from flask import Flask, request, jsonify
import os, base64
import jsonpatch
import random
import logging

app = Flask(__name__)

CERT = os.environ.get('CERT', 'certs/cert.pem')
KEY = os.environ.get('KEY', 'certs/key.pem')

class AdmissionResponse:
    def __init__(self, a_type, allowed, message, patch=None):
        self.a_type = a_type
        self.allowed = allowed
        self.message = message
        self.patch = patch

    def to_dict(self):
        if self.a_type == 'validating':
            return jsonify({
                "response": {
                    "allowed": self.allowed,
                    "status": {
                        "message": self.message
                    }
                }
            })
        elif self.a_type == 'mutating':
            base64_patch = base64.b64encode(self.patch.to_string().encode("utf-8")).decode("utf-8")
            return jsonify({
                "response": {
                    "allowed": self.allowed,
                    "status": {
                        "message": self.message
                    },
                    "patchType": "JSONPatch",
                    "patch": base64_patch
                }
            })
        else:
            logging.error("ERROR: Invalid AdmissionType. Needs to be 'validating' or 'mutating'.")


@app.route('/mutate/randomuid', methods=['POST'])
def randomuid_webhook_mutate():
    """
    Ensures pods and deployments are ran as a Random UID with 'root' group ownership.
    :return: Admission Mutation Response object.
    """
    request_info = request.get_json()

    uid = _get_random_uid()

    if request_info['request']['kind']['kind'] == 'Deployment':
        patches = [
            {"op": "add", "path": "/spec/template/spec/securityContext/runAsUser", "value": uid},
            {"op": "add", "path": "/spec/template/spec/securityContext/runAsGroup", "value": 0},
            {"op": "add", "path": "/spec/template/spec/securityContext/fsGroup", "value": 0}
        ]
    elif request_info['request']['kind']['kind'] == 'Pod':
        patches = [
            {"op": "add", "path": "/spec/securityContext/runAsUser", "value": uid},
            {"op": "add", "path": "/spec/securityContext/runAsGroup", "value": 0},
            {"op": "add", "path": "/spec/securityContext/fsGroup", "value": 0}
        ]
    else:
        patches = []

    return AdmissionResponse(
        a_type='mutating',
        allowed=True,
        message = 'Ensuring random UID and Group',
        patch=jsonpatch.JsonPatch(patches)
    )


@app.route('/validate/noprivilege', methods=['POST'])
def block_privilege_webhook_validate():
    """
    Blocks deployment and pod creation if 'allowPrivilegeEscalation' is enabled.
    :return: Admission validation response object.
    """
    request_json = request.get_json()

    # Manages if the request is for a Deployment, since it has different pathing to get to Privilege Escalation.
    if request_json['request']['kind']['kind'] == 'Deployment':
        if 'securityContext' in request_json["request"]["object"]["spec"]['template']['spec'] and 'allowPrivilegeEscalation' in request_json["request"]["object"]["spec"]['template']['spec']['securityContext'] and request_json["request"]["object"]["spec"]['securityContext']['allowPrivilegeEscalation']:
            logging.error('BLOCKED: Encountered pod attempting privilege escalation.')
            return AdmissionResponse(
                a_type='validating',
                allowed=False,
                message='Privilege escalation not allowed.'
            )

        for container_spec in request_json["request"]["object"]["spec"]['template']['spec']["containers"]:
            logging.error('BLOCKED: Encountered container within attempting privilege escalation.')
            if 'securityContext' in container_spec and 'allowPrivilegeEscalation' in container_spec['securityContext'] and container_spec['securityContext']['allowPrivilegeEscalation']:
                return AdmissionResponse(
                    a_type='validating',
                    allowed=False,
                    message='Privilege escalation not allowed.'
                )

    # Manages if the request is for a Pod, since it has different pathing to get to Privilege Escalation.                                                             
    elif request_json['request']['kind']['kind'] == 'Pod':
        if 'securityContext' in request_json["request"]["object"]["spec"] and 'allowPrivilegeEscalation' in request_json["request"]["object"]["spec"]['securityContext'] and request_json["request"]["object"]["spec"]['securityContext']['allowPrivilegeEscalation']:
            logging.error('BLOCKED: Encountered pod attempting privilege escalation.')
            return AdmissionResponse(
                a_type='validating',
                allowed=False,
                message='Privilege escalation not allowed.'
            )

        for container_spec in request_json["request"]["object"]["spec"]["containers"]:
            if 'securityContext' in container_spec and 'allowPrivilegeEscalation' in container_spec['securityContext'] and container_spec['securityContext']['allowPrivilegeEscalation']:
                logging.critical('BLOCKED: Encountered container within pod attempting privilege escalation.')
                return AdmissionResponse(
                    a_type='validating',
                    allowed=False,
                    message='Privilege escalation not allowed.'
                )

    logging.info('ALLOWED: Deployment/Pod approved.')
    return AdmissionResponse(
        a_type='validating',
        allowed=True,
        message='Privilege escalation not detected. Approved.'
    )


def _get_random_uid():
    """
    Gets a random Integer for the UID.
    :return: Random UID
    """
    return random.randint(100000, 999999)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context=(CERT, KEY))
