<?php
/**
 * Fluent storage implementation for an OAuth 2.0 Auth Code
 *
 * @package   lucadegasperi/oauth2-server-laravel
 * @author    Luca Degasperi <luca@lucadegasperi.com>
 * @copyright Copyright (c) Luca Degasperi
 * @licence   http://mit-license.org/
 * @link      https://github.com/lucadegasperi/oauth2-server-laravel
 */

namespace LucaDegasperi\OAuth2Server\Storage\Mongo;

use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Storage\AuthCodeInterface;
use Carbon\Carbon;

class FluentAuthCode extends FluentAdapter implements AuthCodeInterface
{
    /**
     * Get the auth code
     * @param  string $code
     * @return \League\OAuth2\Server\Entity\AuthCodeEntity
     */
    public function get($code)
    {
        $result = DB::collection('oauth_sessions')
            ->where('auth_code.id', $code)
            ->where('auth_code.expire_time', '>=', time())
            ->select('auth_code')
            ->first();

        if (is_null($result)) {
            return null;
        }

        return (new AuthCodeEntity($this->getServer()))
            ->setId($result['id'])
            ->setRedirectUri($result['redirect_uri'])
            ->setExpireTime((int)$result['expire_time']);
    }

    /**
     * Get the scopes for an access token
     * @param  \League\OAuth2\Server\Entity\AuthCodeEntity $token The auth code
     * @return array Array of \League\OAuth2\Server\Entity\ScopeEntity
     */
    public function getScopes(AuthCodeEntity $token)
    {
        $result = DB::collection('oauth_sessions')
            ->where('auth_code.id', $token->getId())
            ->select('auth_code.scopes')
            ->first();

        $scopes = [];

        foreach ($result as $scope) {

            $scopes[] = (new ScopeEntity($this->getServer()))->hydrate([
               'id' => $scope['id'],
            ]);
        }

        return $scopes;
    }

    /**
     * Associate a scope with an access token
     * @param  \League\OAuth2\Server\Entity\AuthCodeEntity $token The auth code
     * @param  \League\OAuth2\Server\Entity\ScopeEntity $scope The scope
     * @return void
     */
    public function associateScope(AuthCodeEntity $token, ScopeEntity $scope)
    {
        DB::collection('oauth_sessions')
            ->where('auth_code.id', $token->getId())
            ->push('auth_code.scopes', [
                'id' => $scope->getId(),
                'created_at'      => Carbon::now(),
            ]);
    }

    /**
     * Delete an access token
     * @param  \League\OAuth2\Server\Entity\AuthCodeEntity $token The access token to delete
     * @return void
     */
    public function delete(AuthCodeEntity $token)
    {
        DB::collection('oauth_sessions')
            ->where('auth_code.id', $token->getId())
            ->unset('auth_code');
    }


    /**
     * Create an auth code.
     * @param string $token The token ID
     * @param integer $expireTime Token expire time
     * @param integer $sessionId Session identifier
     * @param string $redirectUri Client redirect uri
     *
     * @return void
     */
    public function create($token, $expireTime, $sessionId, $redirectUri)
    {
        $ok = DB::collection('oauth_sessions')
            ->where('id', $sessionId)
            ->update([
                'auth_code' => [
                    'id'              => $token,
                    'redirect_uri'    => $redirectUri,
                    'expire_time'     => $expireTime,
                    'created_at' => Carbon::now(),
                    'updated_at' => Carbon::now()
                ]
            ]);

        if($ok == 0) {
            throw new ServerErrorException('unable to create auth code: no session exists');
        }
    }
}
