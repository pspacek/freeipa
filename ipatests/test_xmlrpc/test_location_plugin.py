#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import pytest

from ipalib import errors, api
from ipatests.test_xmlrpc.tracker.location_plugin import LocationTracker
from ipatests.test_xmlrpc.tracker.server_plugin import ServerTracker
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test,
    raises_exact,
)
from ipapython.dnsutil import DNSName


@pytest.fixture(scope='class', params=[u'location1', u'sk\xfa\u0161ka.idna'])
def location(request):
    tracker = LocationTracker(request.param)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def location_invalid(request):
    tracker = LocationTracker(u'invalid..location')
    return tracker


@pytest.fixture(scope='class')
def location_absolute(request):
    tracker = LocationTracker(u'invalid.absolute.')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def server(request):
    tracker = ServerTracker(api.env.host)
    return tracker


@pytest.mark.tier1
class TestNonexistentIPALocation(XMLRPC_test):
    def test_retrieve_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: location not found' % location.idnsname)):
            command()

    def test_update_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_update_command(updates=dict(
            description=u'Nope'))
        with raises_exact(errors.NotFound(
                reason=u'%s: location not found' % location.idnsname)):
            command()

    def test_delete_nonexistent(self, location):
        location.ensure_missing()
        command = location.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: location not found' % location.idnsname)):
            command()

@pytest.mark.tier1
class TestInvalidIPALocations(XMLRPC_test):
    def test_invalid_name(self, location_invalid):
        command = location_invalid.make_create_command()
        with raises_exact(errors.ConversionError(
                name=u'name',
                error=u"empty DNS label")):
            command()

    def test_invalid_absolute(self, location_absolute):
        command = location_absolute.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'name', error=u'must be relative')):
            command()


@pytest.mark.tier1
class TestCRUD(XMLRPC_test):
    def test_create_duplicate(self, location):
        location.ensure_exists()
        command = location.make_create_command(force=True)
        with raises_exact(errors.DuplicateEntry(
                message=u'location with name "%s" already exists' %
                        location.idnsname)):
            command()

    def test_retrieve_simple(self, location):
        location.retrieve()

    def test_retrieve_all(self, location):
        location.retrieve(all=True)

    def test_search_simple(self, location):
        location.find()

    def test_search_all(self, location):
        location.find(all=True)

    def test_update_simple(self, location):
        location.update(dict(
                description=u'Updated description',
            ),
            expected_updates=dict(
                description=[u'Updated description'],
            ))
        location.retrieve()

    def test_try_rename(self, location):
        location.ensure_exists()
        command = location.make_update_command(
            updates=dict(setattr=u'idnsname=changed'))
        with raises_exact(errors.NotAllowedOnRDN()):
            command()

    def test_delete_location(self, location):
        location.delete()


@pytest.mark.tier1
class TestLocationsServer(XMLRPC_test):

    def test_add_nonexistent_location_to_server(self, server):
        command = server.make_update_command(
            updates=dict(
                ipalocation_location=DNSName(u'nonexistent-location'),
            )
        )
        with raises_exact(errors.NotFound(reason="IPA Location not found")):
            command()

    def test_add_location_to_server(self, location, server):
        location.ensure_exists()
        server.update(
            dict(ipalocation_location=location.idnsname_obj),
            expected_updates=dict(
                ipalocation_location=[location.idnsname_obj],
            )
        )
        location.add_server_to_location(server.server_name)
        location.retrieve()

    def test_retrieve(self, server):
        server.retrieve()

    def test_retrieve_all(self, server):
        server.retrieve(all=True)

    def test_search_server_with_location(self, location, server):
        command = server.make_find_command(
            server.server_name, in_location=location.idnsname_obj)
        result = command()
        server.check_find(result)

    def test_search_server_without_location(self, location, server):
        command = server.make_find_command(
            server.server_name, not_in_location=location.idnsname_obj)
        result = command()
        server.check_find_nomatch(result)

    def test_remove_location_from_server(self, location, server):
        server.update(dict(ipalocation_location=None))
        location.remove_server_from_location(server.server_name)
        location.retrieve()


@pytest.mark.tier1
class TestReferintLocation(XMLRPC_test):
    def test_location_referint(self, location, server):
        location.ensure_exists()
        server.update(
            dict(ipalocation_location=location.idnsname_obj),
            expected_updates=dict(
                ipalocation_location=[location.idnsname_obj],
            )
        )
        command = location.make_delete_command(force=True)
        command()
        location.track_delete()
        # here referint plugins should remove location from servers
        del server.attrs['ipalocation_location']
        server.retrieve()
