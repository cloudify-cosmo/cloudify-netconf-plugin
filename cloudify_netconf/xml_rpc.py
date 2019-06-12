# Copyright (c) 2015-2019 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from urlparse import urlparse
from lxml import etree
import time
import requests

from cloudify_common_sdk import exceptions
import cloudify_terminal_sdk.netconf_connection as netconf_connection
from cloudify.decorators import operation
from cloudify import exceptions as cfy_exc
from cloudify_common_sdk import filters
import cloudify_netconf.utils as utils


def _generate_hello(xmlns, netconf_namespace, capabilities):
    """generate initial hello message with capabilities"""
    if not capabilities:
        capabilities = []
    if netconf_connection.NETCONF_1_0_CAPABILITY not in capabilities:
        capabilities.append(netconf_connection.NETCONF_1_0_CAPABILITY)
    if netconf_connection.NETCONF_1_1_CAPABILITY not in capabilities:
        capabilities.append(netconf_connection.NETCONF_1_1_CAPABILITY)
    hello_dict = {
        netconf_namespace + '@capabilities': {
            netconf_namespace + '@capability': capabilities
        }
    }

    hello_xml = utils.generate_xml_node(
        hello_dict,
        xmlns,
        netconf_namespace + '@hello'
    )
    return etree.tostring(
        hello_xml, pretty_print=True, xml_declaration=True,
        encoding='UTF-8'
    )


def _generate_goodbye(xmlns, netconf_namespace, message_id):
    """general final goodbye message"""
    goodbye_dict = {
        netconf_namespace + '@close-session': None,
        '_@@message-id': message_id
    }
    goodbye_xml = utils.generate_xml_node(
        goodbye_dict,
        xmlns,
        netconf_namespace + '@rpc'
    )
    return etree.tostring(
        goodbye_xml, pretty_print=True, xml_declaration=True,
        encoding='UTF-8'
    )


def _server_support_1_1(xmlns, netconf_namespace, response):
    xml_node = etree.XML(response)
    xpath = (
        "/%s:hello/%s:capabilities/%s:capability" % (
            netconf_namespace, netconf_namespace, netconf_namespace
        )
    )
    capabilities = xml_node.xpath(xpath, namespaces=xmlns)
    for node in capabilities:
        xml_dict = utils.generate_dict_node(node, xmlns)
        value = xml_dict.get(netconf_namespace + '@capability')
        if value == netconf_connection.NETCONF_1_1_CAPABILITY:
            return True
    return False


def _have_error(reply):
    # error check
    # https://tools.ietf.org/html/rfc6241#section-4.3
    error = None

    errors = []
    for k in reply:
        # skip attributes
        if k[:2] == "_@":
            continue
        if 'rpc-error' == k or '@rpc-error' == k[-len('@rpc-error'):]:
            # we can have list of rpc-errors with different namespaces
            if not isinstance(reply[k], list):
                # only one error with such namespace
                errors.append(reply[k])
            else:
                # we can combine several errors lists
                errors += reply[k]

    if not errors:
        return

    for error in errors:
        if not error:
            # we have empty rpc-error?
            raise cfy_exc.RecoverableError(
                "Empty error struct:" + str(errors)
            )

        # server can send warning as error, lets check
        error_severities = []
        for k in error:
            # skip attributes
            if k[:2] == "_@":
                continue
            if (
                'error-severity' == k or
                '@error-severity' == k[-len('@error-severity'):]
            ):
                # and error severity that we found
                error_severities.append(error[k])
        for error_severity in error_severities:
            if error_severity != 'warning':
                raise cfy_exc.RecoverableError(
                    "We have error in reply: {}".format(repr(errors)))


def _search_error(reply, netconf_namespace):
    # recursive search for error tag, slow and dangerous
    if isinstance(reply, basestring):
        return
    elif isinstance(reply, list):
        for tag in reply:
            _search_error(tag, netconf_namespace)
    elif isinstance(reply, dict):
        _have_error(reply)
        for tag_name in reply:
            _search_error(reply[tag_name], netconf_namespace)
            if tag_name.find("@rpc-error") != -1 and tag_name[:2] != "_@":
                # repack to detect error with different namespace
                _have_error({'rpc-error': reply[tag_name]})


def _check_reply_for_errors(reply, netconf_namespace, deep_error_check=False):
    if deep_error_check:
        # only for case when we have errors in the middle of message
        # is not described in https://tools.ietf.org/html/rfc6241#section-4.3
        # but can be in wild life
        _search_error(reply, netconf_namespace)
    else:
        _have_error(reply)

    return reply


def _parse_response(ctx, xmlns, netconf_namespace, response,
                    strict_check=False, deep_error_check=False):
    """parse response from server with check to rpc-error"""
    if strict_check:
        try:
            xml_node = etree.XML(response)
        except etree.XMLSyntaxError as e:
            raise cfy_exc.NonRecoverableError(
                "Syntax error in xml %s" % str(e)
            )
    else:
        # for case when we recieved not fully correct xml
        parser = etree.XMLParser(recover=True)
        xml_node = etree.XML(response, parser)

    xml_dict = utils.generate_dict_node(xml_node, xmlns)

    try:
        if 'rpc-reply' not in xml_dict and \
                (netconf_namespace + '@rpc-reply') not in xml_dict:
            ctx.logger.error(
                'Unexpected key in response: {response}'.format(
                    response=filters.shorted_text(xml_dict)))
        reply = \
            [v for k, v in xml_dict.viewitems()
             if 'rpc-reply' in k][0]
    except IndexError:
        raise cfy_exc.NonRecoverableError(
            'unexpected reply struct: {0}'.format(xml_dict)
        )

    _check_reply_for_errors(reply, netconf_namespace, deep_error_check)

    return reply


def _merge_ns(base, override):
    """we can have several namespaces in properties and in call"""
    new_ns = {}
    for ns in base:
        new_ns[ns] = base[ns]

    for ns in override:
        new_ns[ns] = override[ns]

    return new_ns


def _run_one_string(ctx, netconf, rpc_string, xmlns, netconf_namespace,
                    strict_check, deep_error_check):
    ctx.logger.info(
        "Checks: xml validation: {strict_check}, "
        "rpc_error deep check: {deep_error_check} "
        .format(strict_check=strict_check,
                deep_error_check=deep_error_check)
    )
    ctx.logger.debug("Sent: {message}"
                     .format(message=filters.shorted_text(rpc_string)))

    # cisco send new line before package, so need strip
    try:
        response = netconf.send(rpc_string).strip()
    except exceptions.NonRecoverableError as e:
        # use str instead, for fully hide traceback and orignal exception name
        raise cfy_exc.NonRecoverableError(str(e))

    ctx.logger.debug("Recieved: {response}"
                     .format(response=filters.shorted_text(response)))

    response_dict = _parse_response(
        ctx, xmlns, netconf_namespace, response, strict_check, deep_error_check
    )
    ctx.logger.debug("Package: {response}"
                     .format(response=filters.shorted_text(response_dict)))
    return response_dict


def _run_one(ctx, netconf, message_id, operation, netconf_namespace, data,
             xmlns, strict_check=False, deep_error_check=False):
    """run one call by netconf connection"""
    # rpc
    ctx.logger.info("call: {call}".format(call=operation))
    parent = utils.rpc_gen(
        message_id, operation, netconf_namespace, data, xmlns
    )

    # send rpc
    rpc_string = etree.tostring(
        parent, pretty_print=True, xml_declaration=True,
        encoding='UTF-8'
    )

    return _run_one_string(ctx, netconf, rpc_string, xmlns, netconf_namespace,
                           strict_check, deep_error_check)


def _lock(ctx, name, lock, netconf, message_id, netconf_namespace, xmlns,
          strict_check):
    """lock database by name"""
    operation = "@lock" if lock else "@unlock"
    data = {
        netconf_namespace + "@target": {
            name: {}
        }
    }
    _run_one(
        ctx, netconf, message_id, netconf_namespace + operation,
        netconf_namespace, data, xmlns, strict_check
    )


def _discard_changes(ctx, netconf, message_id, netconf_namespace, xmlns,
                     strict_check):
    """discard changes in candidate database"""
    operation = "@discard-changes"
    _run_one(
        ctx, netconf, message_id, netconf_namespace + operation,
        netconf_namespace, {}, xmlns, strict_check
    )


def _copy(ctx, front, back, netconf, message_id, netconf_namespace, xmlns,
          strict_check):
    """copy fron database values to back database"""
    data = {
        netconf_namespace + "@source": {
            front: {}
        },
        netconf_namespace + "@target": {
            back: {}
        }
    }
    _run_one(
        ctx, netconf, message_id, netconf_namespace + "@copy-config",
        netconf_namespace, data, xmlns, strict_check
    )


def _update_data(data, operation, netconf_namespace, back):
    """update operation with database name"""
    if operation != 'rfc6020@edit-config':
        return
    if not back:
        return
    if "target" in data:
        if not data["target"]:
            data["target"] = {back: None}
        return
    if netconf_namespace + "@target" in data:
        if data[netconf_namespace + "@target"]:
            return
    data[netconf_namespace + "@target"] = {back: None}


def _run_templates(ctx, netconf, templates, template_params, netconf_namespace,
                   xmlns, strict_check, deep_error_check):
    for template in templates:
        # initially empty
        if not template:
            continue

        template = template.strip()
        # empty after strip
        if not template:
            continue

        if not template_params:
            template_params = {}

        # supply ctx for template for reuse runtime params
        template_params['ctx'] = ctx
        rpc_string = filters.render_template(template, template_params)

        _run_one_string(ctx, netconf, rpc_string, xmlns, netconf_namespace,
                        strict_check, deep_error_check)


def _run_calls(ctx, netconf, message_id, netconf_namespace, xmlns, calls,
               back_database, strict_check):
    # we can have several calls in one session,
    # like lock, edit-config, unlock
    for call in calls:
        deep_error_check = call.get('deep_error_check')
        operation = call.get('action')
        if not operation:
            ctx.logger.info("No operations")
            continue
        data = call.get('payload', {})

        message_id += 1

        if "@" not in operation:
            operation = "_@" + operation

        _update_data(data, operation, netconf_namespace, back_database)

        response_dict = _run_one(
            ctx, netconf, message_id, operation, netconf_namespace, data,
            xmlns, strict_check, deep_error_check
        )

        # save results to runtime properties
        save_to = call.get('save_to')
        if save_to:
            ctx.instance.runtime_properties[save_to] = response_dict
            ctx.instance.runtime_properties[save_to + "_ns"] = xmlns


def _get_template(ctx, template_location):
    parse_result = urlparse(template_location)
    if all([parse_result.scheme, parse_result.path]):
        if parse_result.scheme == 'file':
            with open(parse_result.path) as tmpl_f:
                return tmpl_f.read()
        else:
            return requests.get(template_location).content
    else:
        return ctx.get_resource(template_location)


def _run_in_database(ctx, netconf, message_id, netconf_namespace, xmlns, calls,
                     templates, kwargs, strict_check):
    """Change current database and run action"""
    if 'back_database' in kwargs and 'front_database' in kwargs:
        message_id += 1
        _copy(
            ctx, kwargs['front_database'], kwargs['back_database'],
            netconf, message_id, netconf_namespace, xmlns, strict_check
        )

    try:
        if calls:
            _run_calls(ctx, netconf, message_id, netconf_namespace, xmlns,
                       calls, kwargs.get('back_database'), strict_check)
        elif templates:
            template_params = kwargs.get('params')
            deep_error_check = kwargs.get('deep_error_check')
            ctx.logger.debug("Params for template {template_params}".format(
                template_params=filters.shorted_text(template_params)))
            _run_templates(ctx, netconf, templates, template_params,
                           netconf_namespace, xmlns, strict_check,
                           deep_error_check)

        if 'back_database' in kwargs and 'front_database' in kwargs:
            message_id += 1
            _copy(
                ctx, kwargs['back_database'], kwargs['front_database'],
                netconf, message_id, netconf_namespace, xmlns, strict_check
            )

    except (cfy_exc.NonRecoverableError, cfy_exc.RecoverableError) as e:
        # discard only if we know that used candidate database
        if 'back_database' in kwargs and 'front_database' in kwargs:
            ctx.logger.info("Discard changes")
            message_id += 1
            _discard_changes(ctx, netconf, message_id, netconf_namespace,
                             xmlns, strict_check)
        raise e
    return message_id


def _run_in_locked(ctx, netconf, message_id, netconf_namespace, xmlns, calls,
                   templates, kwargs, strict_check):
    """Run actions in locked state"""
    if 'lock' in kwargs:
        for name in kwargs['lock']:
            message_id += 1
            _lock(
                ctx, name, True, netconf, message_id, netconf_namespace,
                xmlns, strict_check
            )
    try:
        message_id = _run_in_database(
            ctx=ctx, netconf=netconf, message_id=message_id,
            netconf_namespace=netconf_namespace, xmlns=xmlns,
            calls=calls, templates=templates, kwargs=kwargs,
            strict_check=strict_check)
    finally:
        # unlock databases
        if 'lock' in kwargs:
            for name in kwargs['lock']:
                message_id += 1
                _lock(
                    ctx, name, False, netconf, message_id, netconf_namespace,
                    xmlns, strict_check
                )
    return message_id


@operation(resumable=True)
def run(ctx, **kwargs):
    """main entry point for all calls"""

    calls = kwargs.get('calls', [])

    templates_locs = kwargs.get('templates', [])
    template = kwargs.get('template')

    templates = []
    for tmpl_loc in templates_locs:
        templates.append(_get_template(ctx, tmpl_loc))

    if template:
        templates.extend(_get_template(ctx, template).split("]]>]]>"))

    if not calls and not templates:
        ctx.logger.info("Please provide calls or template")
        return

    # credentials
    properties = ctx.node.properties
    netconf_auth = properties.get('netconf_auth', {})
    netconf_auth.update(kwargs.get('netconf_auth', {}))
    user = netconf_auth.get('user')
    password = netconf_auth.get('password')
    key_content = netconf_auth.get('key_content')
    port = int(netconf_auth.get('port', 830))
    ip_list = netconf_auth.get('ip')
    if isinstance(ip_list, basestring):
        ip_list = [ip_list]
    # save logs to debug file
    log_file_name = None
    if netconf_auth.get('store_logs'):
        log_file_name = (
            "/tmp/netconf-{execution_id}_{instance_id}_{workflow_id}.log"
            .format(execution_id=str(ctx.execution_id),
                    instance_id=str(ctx.instance.id),
                    workflow_id=str(ctx.workflow_id))
        )
        ctx.logger.info(
            "Communication logs will be saved to {log_file_name}".format(
                log_file_name=log_file_name)
        )

    strict_check = kwargs.get('strict_check', True)

    # if node contained in some other node, try to overwrite ip
    if not ip_list:
        ip_list = [ctx.instance.host_ip]
        ctx.logger.info("Used host from container: {ip_list}".format(
            ip_list=filters.shorted_text(ip_list)))
    # check minimal amout of credentials
    if not port or not ip_list or not user or (
        not password and not key_content
    ):
        raise cfy_exc.NonRecoverableError(
            "please check your credentials"
        )

    # some random initial message id, for have different between calls
    message_id = int((time.time() * 100) % 100 * 1000)

    # xml namespaces and capabilities
    xmlns = properties.get('metadata', {}).get('xmlns', {})

    # override by system namespaces
    xmlns = _merge_ns(xmlns, properties.get('base_xmlns', {}))

    netconf_namespace, xmlns = utils.update_xmlns(
        xmlns
    )
    capabilities = properties.get('metadata', {}).get('capabilities')

    # connect
    ctx.logger.info("use {user}@{ip_list}:{port} for login".format(
        user=user, ip_list=ip_list, port=port))
    hello_string = _generate_hello(
        xmlns, netconf_namespace, capabilities
    )
    ctx.logger.debug("Sent: {message}"
                     .format(message=filters.shorted_text(hello_string)))

    netconf = netconf_connection.NetConfConnection(logger=ctx.logger,
                                                   log_file_name=log_file_name)
    for ip in ip_list:
        try:
            capabilities = netconf.connect(
                ip, user, hello_string, password, key_content, port
            )
            ctx.logger.info("Will be used: {ip}".format(ip=ip))
            break
        except Exception as ex:
            ctx.logger.info("Can't connect to {ip} with {ex}".format(
                ip=repr(ip), ex=str(ex)
            ))
    else:
        raise cfy_exc.NonRecoverableError(
            "please check your ip list"
        )

    ctx.logger.debug("Recieved: {capabilities}"
                     .format(capabilities=filters.shorted_text(capabilities)))

    if _server_support_1_1(xmlns, netconf_namespace, capabilities):
        ctx.logger.info("use version 1.1 of netconf protocol")
        netconf.current_level = netconf_connection.NETCONF_1_1_CAPABILITY
    else:
        ctx.logger.info("use version 1.0 of netconf protocol")

    try:
        message_id = _run_in_locked(
            ctx=ctx, netconf=netconf, message_id=message_id,
            netconf_namespace=netconf_namespace, xmlns=xmlns,
            calls=calls, templates=templates, kwargs=kwargs,
            strict_check=strict_check)
    finally:
        # goodbye
        ctx.logger.info("Connection close")
        message_id += 1
        goodbye_string = _generate_goodbye(
            xmlns, netconf_namespace, message_id
        )
        ctx.logger.debug("Sent: {message}"
                         .format(message=filters.shorted_text(goodbye_string)))

        response = netconf.close(goodbye_string)
        ctx.logger.debug("Recieved: {message} "
                         .format(message=filters.shorted_text(response)))
