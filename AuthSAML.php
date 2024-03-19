<?php

/*
 * LimeSurvey SAML authentication Plugin for Limesurvey
 * @auhtor : Frank Niesten <https://github.com/Frankniesten>
 * @author : Panagiotis Karatakis <https://github.com/karatakis>
 * @author : Denis Chenu <https://sondages.pro>
 * @license: GNU General Public License v3.0
 * @version 1.1.2
 *
 * This plugin is based on the following LimeSurvey Plugins:
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/Authwebserver/Authwebserver.php
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/AuthLDAP/AuthLDAP.php
 * URL: https://github.com/pitbulk/limesurvey-saml
 * URL: https://github.com/Frankniesten/Limesurvey-SAML-Authentication
 * URL: https://github.com/auth-it-center/Limesurvey-SAML-Authentication
 */

class AuthSAML extends LimeSurvey\PluginManager\AuthPluginBase
{
    protected $storage = 'DbStorage';
    protected $ssp = null;

    protected static $description = 'SAML authentication';
    protected static $name = 'AuthSAML';

    protected $settings = array(
        'simplesamlphp_path' => array(
            'type' => 'string',
            'label' => 'Path to the SimpleSAMLphp folder',
            'default' => '/usr/share/simplesamlphp',
        ),
        'simplesamlphp_cookie_session_storage' => array(
            'type' => 'checkbox',
            'label' => 'Does simplesamlphp use cookie as a session storage ?',
            'default' => true,
        ),
        'saml_authsource' => array(
            'type' => 'string',
            'label' => 'SAML authentication source',
            'default' => 'limesurvey',
        ),
        'saml_uid_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as username',
            'default' => 'uid',
        ),
        'saml_mail_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as email',
            'default' => 'mail',
        ),
        'saml_name_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as name',
            'default' => 'cn',
        ),
        'auto_create_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto create users',
            'default' => true,
        ),
        'auto_update_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
        ),
        'force_saml_login' => array(
            'type' => 'checkbox',
            'label' => 'Force SAML login.',
            'default' => false,
        ),
        'authtype_base' => array(
            'type' => 'string',
            'label' => 'Authtype base',
            'default' => 'Authdb',
        ),
        'storage_base' => array(
            'type' => 'string',
            'label' => 'Storage base',
            'default' => 'DbStorage',
        ),
        'logout_redirect' => array(
            'type' => 'string',
            'label' => 'Logout Redirect URL',
            'default' => '/admin',
        ),
    );

    /**
     * @inheritdoc
     */
    public function init()
    {
        $this->storage = $this->get('storage_base', null, null, 'DbStorage');

        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLogout');

        if (!$this->get('force_saml_login', null, null, false)) {
            $this->subscribe('newLoginForm');
        }
    }

    /**
     * @see event
     * Add AuthLDAP Permission to global Permission
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_saml' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use SAML authentication"),
                'description' => gT("Use SAML authentication"),
                'img' => 'usergroup'
            ),
        ));
    }

    /**
     * @see event
     * Set the auth if needed, connect if authenticated
     **/
    public function beforeLogin()
    {
        if (App()->getSession()->get('auth_saml_invalid')) {
            if ($this->get('force_saml_login', null, null, false)) {
                $invalidAccount = $this->gT('Invalid SAML account for this service');
                throw new CHttpException(403, $invalidAccount);
            }
            return;
        }
        $ssp = $this->get_saml_instance();
        if (is_null($ssp)) {
            return;
        }
        if ($this->get('force_saml_login', null, null, false)) {
            $ssp->requireAuth();
        }

        if ($ssp->isAuthenticated()) {
            $this->setAuthPlugin();
            $this->newUserSession();
        }
    }

    /**
     * @see event
     * Redirect to the logout set if needed
     **/
    public function afterLogout()
    {
        $ssp = $this->get_saml_instance();
        if (is_null($ssp)) {
            return;
        }
        $redirect = $this->get('logout_redirect', null, null, '/admin');
        if ($ssp->isAuthenticated()) {
            Yii::app()->controller->redirect($ssp->getLogoutUrl($redirect));
            Yii::app()->end();
        }
    }

    /**
     * @see event
     * Add the content needed for SAML login in login form
     **/
    public function newLoginForm()
    {
        $newLoginFormEvent = $this->getEvent();
        $authtype_base = $this->get('authtype_base', null, null, 'Authdb');
        if (App()->getSession()->get('auth_saml_invalid')) {
            $invalidAccount = $this->gT('Invalid SAML account for this service');
            $content = '<div class="alert alert-warning">' . $invalidAccount . '</div>';
            $newLoginFormEvent->getContent($authtype_base)->addContent($content, 'prepend');
            return;
        }
        $ssp = $this->get_saml_instance();
        if (is_null($ssp)) {
            return;
        }
        $description = $this->gT('Click on that button to initiate SAML Login');
        $imageUrl = Yii::app()->getConfig('imageurl') . '/saml_logo.gif';
        $imageAlt = $this->gT('SAML Login');
        /* No usage of twig : LimeSurvey twig replaced by simplesamlphp due to autoload
         * Break on limesurvey 3 and 5
         * @todo : find a way to fix it, or use twig only for 6
         **/
        $content = '<div class="saml-container">' .
                    '<div class="text-center">' . $description . '</div>' .
                    '<div class="text-center">' .
                    '<a href="' . $ssp->getLoginURL() . '" title="' . $imageAlt . '" class="btn btn-primary">' .
                    '<img src="' . $imageUrl . '" alt="' . $imageAlt . '">' .
                    '</a>' .
                    '</div>' .
                    '</div>';
        $newLoginFormEvent->getContent($authtype_base)->addContent($content, 'prepend');
    }

    /**
     * @see event
     * Create or update user if authneticated by SAML
     **/
    public function newUserSession()
    {
        $oEvent = $this->getEvent();
        $identity = $oEvent->get('identity');
        if ($identity->plugin != 'AuthSAML') {
            return;
        }
        $ssp = $this->get_saml_instance();
        if (is_null($ssp)) {
            return;
        }
        if ($ssp->isAuthenticated()) {
            $sUser = $this->getUserName();
            $name = $this->getUserCommonName();
            $mail = $this->getUserMail();

            $oUser = $this->api->getUserByName($sUser);
            $auto_create_users = $this->get('auto_create_users', null, null, true);

            if (is_null($oUser) and $auto_create_users) {
                // Create new user
                $oUser = new User();
                $oUser->users_name = $sUser;
                $oUser->setPassword(createPassword());
                $oUser->full_name = $name;
                $oUser->parent_id = 1;
                $oUser->email = $mail;

                if ($oUser->save()) {
                    $permission = new Permission();
                    Permission::model()->setGlobalPermission($oUser->uid, 'auth_saml');
                    $oUser = $this->api->getUserByName($sUser);
                    $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
                    $this->setAuthSuccess($oUser);
                } else {
                    $this->subscribe('afterFailedLoginAttempt');
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                }
            } elseif (is_null($oUser)) {
                $this->subscribe('afterFailedLoginAttempt');
                $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
            } elseif (!Permission::model()->hasGlobalPermission('auth_saml', 'read', $oUser->uid)) {
                $this->subscribe('afterFailedLoginAttempt');
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, $this->gT('Invalid SAML account for this service'));
            } else {
                /* @todo Check if user have still access (expire and active) */
                // *** Update user ***
                $auto_update_users = $this->get('auto_update_users', null, null, true);
                if ($auto_update_users) {
                    $changes = array (
                        'full_name' => $name,
                        'email' => $mail,
                    );
                    User::model()->updateByPk($oUser->uid, $changes);
                    $oUser = $this->api->getUserByName($sUser);
                }
                $this->setAuthSuccess($oUser);
            }
        }
        $flag = $this->get('simplesamlphp_cookie_session_storage', null, null, true);
        if ($flag) {
            /* if class already exist : use it, else call
             * @see https://github.com/auth-it-center/Limesurvey-SAML-Authentication/pull/6#discussion_r1529844452
             **/
            if (class_exists('SimpleSAML_Session')) {
                $session = SimpleSAML_Session::getSessionFromRequest();
            } else {
                $session = \SimpleSAML\Session::getSessionFromRequest();
            }
            $session = \SimpleSAML\Session::getSessionFromRequest();
            $session->cleanup();
        }
    }

    /**
     * Initialize SAML authentication
     * @return null|\SimpleSAML
     */
    public function get_saml_instance()
    {
        if ($this->ssp == null) {
            $simplesamlphp_path = $this->get('simplesamlphp_path', null, null, '/var/www/simplesamlphp');
            if (!is_file($simplesamlphp_path . '/lib/_autoload.php')) {
                return null;
            }
            require_once($simplesamlphp_path . '/lib/_autoload.php');
            $saml_authsource = $this->get('saml_authsource', null, null, 'limesurvey');
            $this->ssp = new \SimpleSAML\Auth\Simple($saml_authsource);
        }
        return $this->ssp;
    }

    /**
     * Get Userdata from SAML Attributes
     * @return string
     */
    protected function getUserName()
    {

        if ($this->_username == null) {
            $username = $this->getUserNameAttribute();
            if ($username !== false) {
                $this->setUsername($username);
            }
        }
        return $this->_username;
    }

    /**
     * Get attribute used for user name
     * @return string|false
     */
    private function getUserNameAttribute()
    {
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_uid_mapping = $this->get('saml_uid_mapping', null, null, 'uid');
            if (array_key_exists($saml_uid_mapping, $attributes) && !empty($attributes[$saml_uid_mapping])) {
                $username = $attributes[$saml_uid_mapping][0];
                return $username;
            }
        }
        return false;
    }

    /**
     * Get user common name
     * @return string
     */
    private function getUserCommonName()
    {

        $name = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_name_mapping = $this->get('saml_name_mapping', null, null, 'cn');
            if (array_key_exists($saml_name_mapping, $attributes) && !empty($attributes[$saml_name_mapping])) {
                $name = $attributes[$saml_name_mapping][0];
            }
        }
        return $name;
    }

    /**
     * Get user email
     * @return string
     */
    private function getUserMail()
    {
        $mail = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_mail_mapping = $this->get('saml_mail_mapping', null, null, 'mail');
            if (array_key_exists($saml_mail_mapping, $attributes) && !empty($attributes[$saml_mail_mapping])) {
                $mail = $attributes[$saml_mail_mapping][0];
            }
        }
        return $mail;
    }

    /**
     * Set needed part after fail login attempt
     */
    public function afterFailedLoginAttempt()
    {
        App()->getSession()->add('auth_saml_invalid', true);
    }

    /**
     * @see parent:gt
     * To be used with old LimeSurvey version
     * Replace $sEscapeMode to unescaped
     */
    public function translate($sToTranslate, $sEscapeMode = 'unescaped', $sLanguage = null)
    {
        if (is_callable($this, 'gT')) {
            return $this->gT($sToTranslate, $sEscapeMode, $sLanguage);
        }
        return $sToTranslate;
    }
}
