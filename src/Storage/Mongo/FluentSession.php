<?php
/**
 * Fluent storage implementation for an OAuth 2.0 Session
 *
 * @package   lucadegasperi/oauth2-server-laravel
 * @author    Luca Degasperi <luca@lucadegasperi.com>
 * @copyright Copyright (c) Luca Degasperi
 * @licence   http://mit-license.org/
 * @link      https://github.com/lucadegasperi/oauth2-server-laravel
 */

namespace LucaDegasperi\OAuth2Server\Storage\Mongo;

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use Carbon\Carbon;

class FluentSession extends FluentAdapter implements SessionInterface
{
    /**
     * Get a session from it's identifier
     * @param string $sessionId
     * @return \League\OAuth2\Server\Entity\SessionEntity
     */
    public function get($sessionId)
    {
        $result = DB::collection('oauth_sessions')
            ->where('id', $sessionId)
            ->first();

        if(is_null($result)) {
            return null;
        }

        return (new SessionEntity($this->getServer()))
               ->setId($result['id'])
               ->setOwner($result['owner_type'], $result['owner_id']);
    }

    /**
     * Get a session from an access token
     * @param  \League\OAuth2\Server\Entity\AccessTokenEntity $accessToken The access token
     * @return \League\OAuth2\Server\Entity\SessionEntity
     */
    public function getByAccessToken(AccessTokenEntity $accessToken)
    {
        $result = DB::collection('oauth_sessions')
                   ->where('access_token.id', $accessToken->getId())
                   ->first();

        if (is_null($result)) {
            return null;
        }

        return (new SessionEntity($this->getServer()))
               ->setId($result['id'])
               ->setOwner($result['owner_type'], $result['owner_id']);
    }

    /**
     * Get a session's scopes
     * @param  \League\OAuth2\Server\Entity\SessionEntity
     * @return array Array of \League\OAuth2\Server\Entity\ScopeEntity
     */
    public function getScopes(SessionEntity $session)
    {
        $result = DB::collection('oauth_sessions')
                  ->where('id', $session->getId())
                  ->first();

        $scopes = [];

        //TODO: better scope checking?
        $sessionScopes = [
            @$result['scopes'],
            @$result['access_token.scopes'],
        ];

        if (is_null($result))
            return null;

        foreach ($sessionScopeLists as $sessionScopes) {
            foreach ($sessionScopes as $scope) {
                $scopes[] = (new ScopeEntity($this->getServer()))->hydrate([
                    'id' => $scope['id'],
                ]);
            }
        }

        return $scopes;
    }

    /**
     * Create a new session
     * @param  string $ownerType         Session owner's type (user, client)
     * @param  string $ownerId           Session owner's ID
     * @param  string $clientId          Client ID
     * @param  string $clientRedirectUri Client redirect URI (default = null)
     * @return integer The session's ID
     */
    public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null)
    {
        return DB::collections('oauth_sessions')
            ->insertGetId([
                'client_id'  => $clientId,
                'owner_type' => $ownerType,
                'owner_id'   => $ownerId,
                'client_redirect_uri' => $clientRedirectUri,
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now()
            ]);
    }

    /**
     * Associate a scope with a session
     * @param  \League\OAuth2\Server\Entity\SessionEntity $session
     * @param  \League\OAuth2\Server\Entity\ScopeEntity $scope The scopes ID might be an integer or string
     * @return void
     */
    public function associateScope(SessionEntity $session, ScopeEntity $scope)
    {
        DB::collection('oauth_sessions')
            ->where('id', $session->getId())
            ->push('scopes', [
                'session_id' => $session->getId(),
                'scope_id'   => $scope->getId(),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ]);
    }

    /**
     * Get a session from an auth code
     * @param  \League\OAuth2\Server\Entity\AuthCodeEntity $authCode The auth code
     * @return \League\OAuth2\Server\Entity\SessionEntity
     */
    public function getByAuthCode(AuthCodeEntity $authCode)
    {
        $result = DB::colletion('oauth_sessions')
            ->where('auth_code.id', $authCode->getId())
            ->first();

        if (is_null($result)) {
            return null;
        }

        return (new SessionEntity($this->getServer()))
               ->setId($result['id'])
               ->setOwner($result['owner_type'], $result['owner_id']);
    }
}
