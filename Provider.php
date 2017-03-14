<?php

namespace SocialiteProviders\Esia;

use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Symfony\Component\HttpFoundation\RedirectResponse;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'ESIA';

    protected $scopeSeparator = ' ';
    /**
     * {@inheritdoc}
     */
    protected $scopes = ['contacts', 'fullname'];

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->getPortalUrl().'/aas/oauth2/ac', $state);
    }

    public function logout(){
        \Auth::logout();
        \Session::flush();
        \Session::regenerate();
        return new RedirectResponse($this->getPortalUrl().'/idp/ext/Logout'.'?'. http_build_query([
                'client_id' => $this->clientId,
                'redirect_url' => env('APP_URL'),
            ], '', '&', $this->encodingType));
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getPortalUrl().'/aas/oauth2/te';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $id_token = $this->base64urlDecode($token);
        list($header, $payload, $signature) = explode('.', $id_token);
        $payload = json_decode(base64_decode($payload));
        $user_id = $payload->{'urn:esia:sbj_id'};
        $response = $this->getHttpClient()->get($this->getPortalUrl().'/rs/prns/' . $user_id .'?embed=(contacts.elements,addresses.elements)', [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return array_merge(json_decode($response->getBody(), true), ['id' => $user_id]);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $email = array_where($user['contacts']['elements'], function ($value) {
           return $value['type'] === 'EML';
        });
        $email = array_shift($email);
        return (new User())->setRaw($user)->map([
            'id'       => $user['id'],
            'nickname' => $email['value'],
            'name'     => $user['lastName']. ' ' . mb_substr($user['firstName'], 0, 1, 'utf-8') . '.' . mb_substr($user['middleName'], 0, 1, 'utf-8') . '.',
            'email'    => $email['value'],
            'avatar'   => null,
        ]);
    }

    protected function getCodeFields($state = null)
    {
        return array_merge(parent::getCodeFields($state), [
            'client_secret' => $this->getClientSecret($state),
            'timestamp' => date('Y.m.d H:i:s O'),
            'access_type' => 'online',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        $state = $this->getState();
        return [
            'client_id' => $this->clientId,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'client_secret' => $this->getClientSecret($state),
            'state' => $state,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'timestamp' => date('Y.m.d H:i:s O'),
            'token_type' => 'Bearer'


        ];
    }

    protected function getPortalUrl(){
        return env('ESIA_PORTAL','https://esia-portal1.test.gosuslugi.ru');
    }

    protected function getState()
    {
        $data = openssl_random_pseudo_bytes(16);

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    protected function getClientSecret($state)
    {
        return $this->signPKCS7($this->formatScopes($this->getScopes(), $this->scopeSeparator) . date('Y.m.d H:i:s O') . $this->clientId . $state);
    }

    /**
     * Algorithm for singing message which
     * will be send in client_secret param
     *
     * @param string $message
     * @return string
     */
    protected function signPKCS7($message)
    {
        $certContent = file_get_contents(env('ESIA_CERTIFICATE', 'certificate.pem'));
        $keyContent = file_get_contents(env('ESIA_PRIVATE_KEY', 'private_key'));

        $cert = openssl_x509_read($certContent);

        $privateKey = openssl_pkey_get_private($keyContent, env('ESIA_PASSWORD','private_key_password'));

        // random unique directories for sign
        $messageFile = tempnam(sys_get_temp_dir(),'ESIA_'); //$this->tmpPath . DIRECTORY_SEPARATOR . uniqid().'_mes';
        $signFile = tempnam(sys_get_temp_dir(),'ESIA_'); //$this->tmpPath . DIRECTORY_SEPARATOR . uniqid().'_sign';
        file_put_contents($messageFile, $message);

        $signResult = openssl_pkcs7_sign(
            $messageFile,
            $signFile,
            $cert,
            $privateKey,
            []
        );

        /*if ($signResult) {
            $this->writeLog('Sign success');
        } else {
            $this->writeLog('Sign fail');
            $this->writeLog('SSH error: ' . openssl_error_string());
            throw new SignFailException(SignFailException::CODE_SIGN_FAIL);
        }*/

        $signed = file_get_contents($signFile);

        # split by section
        $signed = explode("\n\n", $signed);

        # get third section which contains sign and join into one line
        $signed = explode("\n", $signed[3]);
        $signed = implode('', $signed);

        return $signed;

    }

    protected function base64urlDecode($string)
    {
        return strtr($string, '-_,', '+/=');
    }
}
