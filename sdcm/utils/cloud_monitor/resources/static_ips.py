from logging import getLogger
from libcloud.compute.drivers.gce import GCEAddress
from sdcm.utils.cloud_monitor.common import NA
from sdcm.utils.cloud_monitor.resources import CloudResources
from sdcm.utils.common import list_elastic_ips_aws, aws_tags_to_dict, list_static_ips_gce


LOGGER = getLogger(__name__)


class StaticIP:  # pylint: disable=too-few-public-methods
    def __init__(self, cloud, name, address, region, used_by, owner):  # pylint: disable=too-many-arguments
        self.cloud = cloud
        self.name = name
        self.address = address
        self.region = region
        self.used_by = used_by  # instance to which the static IP is associated
        self.owner = owner

    @property
    def is_used(self):
        if self.used_by != NA:
            return True
        return False


class AwsElasticIP(StaticIP):  # pylint: disable=too-few-public-methods
    def __init__(self, eip, region):
        tags = eip.get('Tags')
        tags_dict = {}
        if tags:
            tags_dict = aws_tags_to_dict(tags)
        super(AwsElasticIP, self).__init__(
            cloud="aws",
            name=tags_dict.get("Name", NA) if tags else NA,
            address=eip['PublicIp'],
            region=region,
            used_by=eip.get('InstanceId', NA),
            owner=tags_dict.get("RunByUser", NA) if tags else NA,
        )


class GceStaticIP(StaticIP):  # pylint: disable=too-few-public-methods
    def __init__(self, static_ip: GCEAddress):
        used_by = static_ip.extra.get("users")
        super(GceStaticIP, self).__init__(
            cloud="gce",
            name=static_ip.name,
            address=static_ip.address,
            region=static_ip.region if isinstance(static_ip.region, str) else static_ip.region.name,
            used_by=used_by[0].rsplit("/", maxsplit=1)[-1] if used_by else NA,
            owner=NA  # currently unsupported, maybe we can store it in description in future
        )


class StaticIPs(CloudResources):
    """Allocated static IPs"""

    def __init__(self, cloud_instances):
        self.cloud_instances = cloud_instances  # needed to identify use when attached to an instance
        super(StaticIPs, self).__init__()

    def get_aws_elastic_ips(self):
        LOGGER.info("Getting AWS Elastic IPs...")
        eips_grouped_by_region = list_elastic_ips_aws(group_as_region=True, verbose=True)
        self["aws"] = [AwsElasticIP(eip, region) for region, eips in eips_grouped_by_region.items() for eip in eips]
        # identify user by the owner of the resource
        cloud_instances_by_id = {instance.instance_id: instance for instance in self.cloud_instances["aws"]}
        for eip in self["aws"]:
            if eip.owner == NA and eip.used_by != NA and cloud_instances_by_id.get(eip.used_by):
                eip.owner = cloud_instances_by_id[eip.used_by].owner
        self.all.extend(self["aws"])

    def get_gce_static_ips(self):
        static_ips = list_static_ips_gce(verbose=True)
        self["gce"] = [GceStaticIP(ip) for ip in static_ips]
        cloud_instances_by_name = {instance.name: instance for instance in self.cloud_instances["gce"]}
        for eip in self["gce"]:
            if eip.owner == NA and eip.used_by != NA and cloud_instances_by_name.get(eip.used_by):
                eip.owner = cloud_instances_by_name[eip.used_by].owner
        self.all.extend(self["gce"])

    def get_all(self):
        self.get_aws_elastic_ips()
        self.get_gce_static_ips()
