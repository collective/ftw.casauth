from AccessControl.requestmethod import postonly
from AccessControl.Permissions import change_configuration
from AccessControl.SecurityInfo import ClassSecurityInfo
from ftw.casauth.cas import service_url
from ftw.casauth.cas import validate_ticket
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import \
    IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from zope import interface

from ftw.casauth.password import generatePassword

# BBB Python 2 compatibility
from six.moves import urllib

manage_addCASAuthenticationPlugin = PageTemplateFile(
    "www/addPlugin", globals(), __name__="manage_addCASAuthenticationPlugin")


def addCASAuthenticationPlugin(
        self, id_, title=None, cas_server_url=None,
        set_props_from_attrs=False, add_unknown_users=False,
        REQUEST=None):
    """Add a CAS authentication plugin
    """
    plugin = CASAuthenticationPlugin(
        id_, title, cas_server_url,
        set_props_from_attrs, add_unknown_users)
    self._setObject(plugin.getId(), plugin)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            "%s/manage_workspace"
            "?manage_tabs_message=CAS+authentication+plugin+added." %
            self.absolute_url()
        )


@interface.implementer(
    IAuthenticationPlugin,
    IChallengePlugin,
    IExtractionPlugin)
class CASAuthenticationPlugin(BasePlugin):
    """Plone PAS plugin for authentication against a CAS server.
    """
    meta_type = "CAS Authentication Plugin"
    security = ClassSecurityInfo()

    # ZMI tab for configuration page
    manage_options = (
        ({'label': 'Configuration',
          'action': 'manage_config'},)
        + BasePlugin.manage_options
    )
    security.declareProtected(change_configuration, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    # Detaults for existing instances created before these were added
    set_props_from_attrs = False
    add_unknown_users = False

    def __init__(
            self, id_, title=None, cas_server_url=None,
            set_props_from_attrs=False, add_unknown_users=False):
        self._setId(id_)
        self.title = title
        if cas_server_url:
            cas_server_url = cas_server_url.rstrip('/')
        self.cas_server_url = cas_server_url

        self.set_props_from_attrs = set_props_from_attrs
        self.add_unknown_users = add_unknown_users

    security.declarePrivate('challenge')

    # Initiate a challenge to the user to provide credentials.
    def challenge(self, request, response, **kw):
        if 'ticket' in request.form:
            return False

        if not self.cas_server_url:
            return False

        response.redirect('%s/login?service=%s' % (
            self.cas_server_url,
            urllib.parse.quote(service_url(request)),
        ), lock=True)
        return True

    security.declarePrivate('extractCredentials')

    # IExtractionPlugin implementation
    # Extracts a CAS service ticket from the request.
    def extractCredentials(self, request):
        if 'ticket' not in request.form:
            return None

        creds = {}
        creds['ticket'] = request.form.get('ticket')
        creds['service_url'] = service_url(request)

        # Avoid having the `ticket` query string param show up in the
        # user's browser's address bar by redirecting back to the
        # service_url, which should have the ticket stripped from it
        request.RESPONSE.redirect(creds['service_url'], lock=True)

        return creds

    security.declarePrivate('authenticateCredentials')

    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):
        # Ignore credentials that are not from our extractor
        extractor = credentials.get('extractor')
        if extractor != self.getId():
            return None

        validation_result = validate_ticket(
            credentials['ticket'],
            self.cas_server_url,
            credentials['service_url'],
        )
        if not validation_result:
            return None
        userid, attrs = validation_result

        result = self.login_user(userid, attrs=attrs)
        if not result:
            return None

        return userid, userid

    def login_user(self, userid, attrs=None):
        pas = self._getPAS()
        info = pas._verifyUser(pas.plugins, user_id=userid)
        if info is None:
            if self.add_unknown_users:
                pas._doAddUser(
                    userid, generatePassword(),
                    roles=('Member',), domains='')
            else:
                return None

        pas.updateCredentials(self.REQUEST, self.REQUEST.RESPONSE, userid, '')
        return True

    def expire_clipboard(self):
        if self.REQUEST.get('__cp', None) is not None:
            self.REQUEST.RESPONSE.expireCookie('__cp', path='/')

    security.declareProtected(change_configuration, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of CAS Authentication Plugin.
        """
        response = REQUEST.response

        self.cas_server_url = REQUEST.form.get(
            'cas_server_url', ''
        ).rstrip('/')
        self.set_props_from_attrs = bool(REQUEST.form.get(
            'set_props_from_attrs',
            CASAuthenticationPlugin.set_props_from_attrs))
        self.add_unknown_users = bool(REQUEST.form.get(
            'add_unknown_users',
            CASAuthenticationPlugin.add_unknown_users))

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))
