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

Vyatta example is valid only for Brocade Vyatta Network OS 4.1 R2 and before run vyatta bluerint run as root on router:
* cd /usr/share/doc/openvpn/examples/sample-keys/
* bash gen-sample-keys.sh

Script name can be different and related to Brocade vRouter version.

## tags name convertions logic:
* a -&gt; tag with name "a" and namespaces will be same as parent
* a@b -&gt; tag with name "b" and namespace a
* _@@a -&gt; attibute with name a and namespace will be same as parent
* _@a@b -&gt; attibute with name b and namespace will be a
* _@@ -&gt; text content for tag

## examples of conversion

### list
from:
{
    b: {
        a: [1, 2, 3],
        c: 4
    }
}

to:
&lt;b&gt;
    &lt;a&gt;1&lt;/a&gt;
    &lt;a&gt;2&lt;/a&gt;
    &lt;a&gt;3&lt;/a&gt;
    &lt;c&gt;4&lt;/c&gt;
&lt;/b&gt;

### dict
from:
{
    b: {
        a: 1,
        c: 2
    }
}

to:
&lt;b&gt;
    &lt;a&gt;1&lt;/a&gt;
    &lt;c&gt;2&lt;/c&gt;
&lt;/b&gt;

### attibutes
from:
{
    b: {
        _@@a: 1,
        _@@: 2
    }
}

to:

&lt;b a=1&gt;
    2
&lt;/b&gt;

### text value for tag with attibutes
from:
{
    b@a: {
        _@c@a: 1,
        _@@: 2,
        _@@g: 3
    }
}

to:
&lt;b:a c:a=1 b:g=3&gt;
    2
&lt;/b:a&gt;
