# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from logging import getLogger

LOG = getLogger(__name__)

API_NAME = 'storage'


def make_client(instance):
    from oio.api.object_storage import ObjectStorageApi

    admin_mode = instance.get_admin_mode()
    endpoint = instance.get_endpoint('storage')
    client = ObjectStorageApi(
        endpoint=endpoint,
        namespace=instance.namespace,
        admin_mode=admin_mode
    )
    return client


def build_option_parser(parser):
    return parser
