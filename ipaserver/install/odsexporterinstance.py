# Authors: Martin Basti <mbasti@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import service
import installutils
import os
import pwd
import grp

import ldap

from ipapython.ipa_log_manager import *
from ipapython.dn import DN
from ipapython import sysrestore, ipautil, ipaldap
from ipaplatform.paths import paths
from ipaplatform import services
from ipalib import errors


class ODSExporterInstance(service.Service):
    def __init__(self, fstore=None, dm_password=None):
        service.Service.__init__(
            self, "ipa-ods-exporter",
            service_desc="IPA OpenDNSSEC exporter daemon",
            dm_password=dm_password,
            ldapi=False,
            autobind=ipaldap.AUTOBIND_DISABLED
        )
        self.dm_password = dm_password
        self.ods_uid = None
        self.ods_gid = None
        self.enable_if_exists = False

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    suffix = ipautil.dn_attribute_property('_suffix')

    def create_instance(self, fqdn, realm_name):
        self.backup_state("enabled", self.is_enabled())
        self.backup_state("running", self.is_running())
        self.fqdn = fqdn
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(self.realm)

        try:
            self.stop()
        except:
            pass

        # get a connection to the DS
        self.ldap_connect()
        # checking status step must be first
        self.step("checking status", self.__check_dnssec_status)
        self.step("setting up DNS Key Exporter", self.__setup_key_exporter)
        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("disabling default signer daemon", self.__disable_signerd)
        self.step("starting DNS Key Exporter", self.__start)
        self.step("configuring DNS Key Exporter to start on boot", self.__enable)
        self.start_creation()

    def __check_dnssec_status(self):
        ods_enforcerd = services.knownservices['ods-enforcerd']

        try:
            self.ods_uid = pwd.getpwnam(ods_enforcerd.get_user_name()).pw_uid
        except KeyError:
            raise RuntimeError("OpenDNSSEC UID not found")

        try:
            self.ods_gid = grp.getgrnam(ods_enforcerd.get_group_name()).gr_gid
        except KeyError:
            raise RuntimeError("OpenDNSSEC GID not found")

    def __enable(self):

        try:
            self.ldap_enable('DNSKeyExporter', self.fqdn, self.dm_password,
                             self.suffix)
        except errors.DuplicateEntry:
            root_logger.error("DNSKeyExporter service already exists")
        self.enable()

    def __setup_key_exporter(self):
        installutils.set_directive(paths.SYSOCNFIG_IPA_ODS_EXPORTER,
                                   'SOFTHSM2_CONF',
                                   paths.DNSSEC_SOFTHSM2_CONF,
                                   quotes=False, separator='=')

    def __setup_principal(self):
        assert self.ods_uid is not None
        dns_exporter_principal = "ipa-ods-exporter/" + self.fqdn + "@" + self.realm
        installutils.kadmin_addprinc(dns_exporter_principal)

        # Store the keytab on disk
        installutils.create_keytab(paths.IPA_ODS_EXPORTER_KEYTAB, dns_exporter_principal)
        p = self.move_service(dns_exporter_principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dns_exporter_principal_dn = DN(
                ('krbprincipalname', dns_exporter_principal),
                ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dns_exporter_principal_dn = p

        # Make sure access is strictly reserved to the ods user
        os.chmod(paths.IPA_ODS_EXPORTER_KEYTAB, 0440)
        os.chown(paths.IPA_ODS_EXPORTER_KEYTAB, 0, self.ods_gid)

        dns_group = DN(('cn', 'DNS Servers'), ('cn', 'privileges'),
                       ('cn', 'pbac'), self.suffix)
        mod = [(ldap.MOD_ADD, 'member', dns_exporter_principal_dn)]

        try:
            self.admin_conn.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception, e:
            root_logger.critical("Could not modify principal's %s entry: %s"
                                 % (dns_exporter_principal_dn, str(e)))
            raise

        # limit-free connection

        mod = [(ldap.MOD_REPLACE, 'nsTimeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsSizeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsIdleTimeout', '-1'),
               (ldap.MOD_REPLACE, 'nsLookThroughLimit', '-1')]
        try:
            self.admin_conn.modify_s(dns_exporter_principal_dn, mod)
        except Exception, e:
            root_logger.critical("Could not set principal's %s LDAP limits: %s"
                                 % (dns_exporter_principal_dn, str(e)))
            raise

    def __disable_signerd(self):
        signerd_service = services.knownservices['ods-signerd']

        self.backup_state("singerd_running", signerd_service.is_running())
        self.backup_state("singerd_enabled", signerd_service.is_enabled())

        # disable default opendnssec signer daemon
        signerd_service.stop()
        signerd_service.mask()

    def __start(self):
        self.start()

    def uninstall(self):
        if not self.is_configured():
            return

        self.print_msg("Unconfiguring %s" % self.service_name)

        running = self.restore_state("running")
        enabled = self.restore_state("enabled")

        if enabled is not None and not enabled:
            self.disable()

        if running is not None and running:
            self.start()

        # restore state of dnssec default signer daemon
        signerd_enabled = self.restore_state("singerd_enabled")
        signerd_running = self.restore_state("singerd_runnning")
        signerd_service = services.knownservices['ods-signerd']

        signerd_service.unmask()

        # service was stopped and disabled by setup
        if signerd_enabled:
            signerd_service.enable()

        if signerd_running:
            signerd_service.start()
