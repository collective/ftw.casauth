# -*- coding: utf-8 -*-
# things lifted from plone.restapi and plone.rest
import json

from AccessControl.SecurityManagement import getSecurityManager
from zope.component import queryMultiAdapter
from zope.interface import Interface, implementer
from zExceptions import Unauthorized


UseRESTAPI = 'ftw.cas.restapi: Use REST API'
_no_content_marker = object()


class IService(Interface):
    """Marker for REST services.
    """


class ICORSPolicy(Interface):
    """Provides methods for processing simple and preflight CORS requests by
       adding access control headers.
    """

    def process_simple_request():
        """Process a simple request"""

    def process_preflight_request():
        """Process a preflight request"""


def json_body(request):
    try:
        data = json.loads(request.get("BODY") or "{}")
    except ValueError:
        raise ValueError("No JSON object could be decoded")
    if not isinstance(data, dict):
        raise ValueError("Malformed body")
    return data


@implementer(IService)
class Service(object):
    """Base class for Plone REST API services"""

    content_type = 'application/json'

    def __call__(self):
        policy = queryMultiAdapter((self.context, self.request), ICORSPolicy)
        if policy is not None:
            if self.request._rest_cors_preflight:
                policy.process_preflight_request()
                return
            else:
                policy.process_simple_request()
        else:
            if self.request._rest_cors_preflight:
                return

        return self.render()

    def __getattribute__(self, name):
        # Preflight requests need to be publicly accessible since they don't
        # include credentials
        if name == "__roles__" and self.request._rest_cors_preflight:
            return ["Anonymous"]
        return super(Service, self).__getattribute__(name)

    def render(self):
        self.check_permission()
        content = self.reply()
        if content is not _no_content_marker:
            self.request.response.setHeader('Content-Type', self.content_type)
            return json.dumps(
                content, indent=2, sort_keys=True, separators=(', ', ': ')
            )

    def check_permission(self):
        sm = getSecurityManager()
        if not sm.checkPermission(UseRESTAPI, self):
            raise Unauthorized('Missing %r permission' % UseRESTAPI)

    def reply(self):
        """Process the request and return a JSON serializable data structure or
           the no content marker if the response body should be empty.
        """
        return _no_content_marker

    def reply_no_content(self, status=204):
        self.request.response.setStatus(status)
        return _no_content_marker
