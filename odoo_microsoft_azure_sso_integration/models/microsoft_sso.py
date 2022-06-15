import json
import simplejson
from odoo import fields, models
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.exceptions import AccessDenied, UserError, ValidationError
import urllib
from odoo import api, fields, models, tools, _
from odoo.http import request

class Res_Users(models.Model):
    _inherit = 'res.users'

    microsoft_refresh_token = fields.Char('Microsoft Refresh Token')

    @api.model
    def microsoft_auth_oauth(self, provider, params):
        access_token = params.get('access_token')
        login = self._microsoft_auth_oauth_signin(provider, params)
        if not login:
            raise AccessDenied()
        return self._cr.dbname, login, access_token

    @api.model
    def _microsoft_generate_signup_values(self, provider, params):
        # import pdb; pdb.set_trace()
        email = params.get('email')
        return {
            'name': params.get('name', email),
            'login': email,
            'email': email,
            'groups_id': [(6,0, [self.env.ref('base.group_user').id])],
            'company_id': 1,
            'oauth_provider_id': provider,
            'oauth_uid': params['user_id'],
            'microsoft_refresh_token': params['microsoft_refresh_token'],
            'oauth_access_token': params['access_token'],
            'active': True
            
        }

    @api.model
    def _microsoft_auth_oauth_signin(self, provider, params):
        # import pdb; pdb.set_trace()
        try:

            oauth_uid = params['user_id']
            all_users = self.sudo().search([
                ("oauth_uid", "=", oauth_uid),
                ('oauth_provider_id', '=', provider)
            ], limit=1)
            if not all_users:
                all_users = self.sudo().search([
                    ("login", "=", params.get('email'))
                ], limit=1)
            if not all_users:
                raise AccessDenied()
            assert len(all_users.ids) == 1
            all_users.sudo().write({
                'oauth_access_token': params['access_token'],
                'microsoft_refresh_token': params['microsoft_refresh_token']})
            return all_users.login
        except AccessDenied as access_denied_exception:
            if self._context and self._context.get('no_user_creation'):
                return None
            vals = self._microsoft_generate_signup_values(provider, params)
            try:
                _, login, _ = self.with_context(
                    mail_create_nosubscribe=True).signup(vals)
                return login
            except (SignupError, UserError):
                raise access_denied_exception

    
class Auth_Oauth_Provider(models.Model):
    """Class defining the configuration values of an OAuth2 provider"""

    _inherit = 'auth.oauth.provider'

    secret_key = fields.Char('Secret Key (Secret Value)')
    client_id = fields.Char('Microsoft Client Id')

    def oauth_token(
            self, type_grant, oauth_provider_rec, code=None,
            refresh_token=None, context=None):
        # import pdb; pdb.set_trace()    
        info = dict(
            grant_type=type_grant,
            redirect_uri=request.env['ir.config_parameter'].sudo().get_param(
                'web.base.url') + '/auth_oauth/microsoft/signin',
            client_id=oauth_provider_rec.client_id,
            client_secret=oauth_provider_rec.secret_key,
        )
        if code:
            info.update({'code': code})
        elif refresh_token:
            info.update({'refresh_token': refresh_token})
        return simplejson.loads(urllib.request.urlopen(
            urllib.request.Request(
                oauth_provider_rec.validation_endpoint,
                urllib.parse.urlencode(info).encode("utf-8"))).read())

