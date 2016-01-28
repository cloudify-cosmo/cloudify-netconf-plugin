# cloudify-netconf-plugin
Cloudify plugin for serializing TOSCA node templates to netconf configuration.
Have support both version of netconf protocol from rfc6242.

Code for now does not support:
* conditional statements with dependencies capabilities available on hardware level,
* validation of complicated types with restriction for type of values (length, regexp and etc.)
* validation of type element in list (unsupported list of some types)
* validation of enums in value and in xml node name
* can be described only input struct for netconf, output(received structures from netconf) does not validated and not described in yaml blueprints.
* complicated structs with list of types can be described only as static(not dynamic) in sophisticated cases
* case when by some condition we have to different scructs, like we send configuration that in case dhcp - contain only flag that we have dhcp configuration,
otherwise we have full scruct that descrive static connection. So if in description we have both fields, in first case we send empty values, so we need to have
2 node types/configurations for dhcp and for static

For check generation:
* xml to yaml: netconfxml2yaml.py cloudify-netconf-plugin/blueprint_examples/rpc.xml
* yaml to xml: yaml2netconfxml.py cloudify-netconf-plugin/blueprint_examples/rpc.yaml
* generate validation rules:
  cd tools/examples
  yang2dsdl -t config turing-machine.yang
  netconfxml2yaml.py config.xml turing-machine-config.rng  turing-machine-config.sch
