<?php
/**
 * Fluent storage implementation for an OAuth 2.0 Access Token
 *
 * @package   lucadegasperi/oauth2-server-laravel
 * @author    Luca Degasperi <luca@lucadegasperi.com>
 * @copyright Copyright (c) Luca Degasperi
 * @licence   http://mit-license.org/
 * @link      https://github.com/lucadegasperi/oauth2-server-laravel
 */

namespace LucaDegasperi\OAuth2Server\Storage\Mongo;

use League\OAuth2\Server\Entity\AbstractTokenEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use Carbon\Carbon;
use League\OAuth2\Server\Exception\ServerErrorException;

class FluentAccessToken extends FluentAdapter implements AccessTokenInterface
{
    /**
      * {@inheritdoc}
      */
    public function get($token)
    {
        $result = DB::collection('oauth_sessions')
            ->where('access_token.id', $token)
            ->select('access_token')
            ->first();

        if (is_null($result)) {
            return null;
        }

        return (new AccessTokenEntity($this->getServer()))
               ->setId($result['id'])
               ->setExpireTime((int)$result['expire_time']);
    }

    /**
      * {@inheritdoc}
      */
    public function getScopes(AccessTokenEntity $token)
    {
        $result = DB::collection('oauth_sessions')
            ->where('access_token.id', $token->getId())
            ->select('access_token.scopes')
            ->first();

        $scopes = [];

        foreach ($result as $accessTokenScope) {
            $scopes[] = (new ScopeEntity($this->getServer()))->hydrate([
                'id' => $scope['id'],
            ]);
        }

        return $scopes;
    }

    /**
      * {@inheritdoc}
      */
    public function create($token, $expireTime, $sessionId)
    {

        $ok = DB::collections('oauth_sessions')
            ->where('id', $sessionId)
            ->update([
                'access_token' => [
                    'id' => $token,
                    'expire_time' => $expireTime,
                    'created_at' => Carbon::now(),
                    'updated_at' => Carbon::now(),
                ],
            ]);

        if($ok == 0) {
            throw new ServerErrorException('unable to create access token: no session exists');
        }

        return (new AccessTokenEntity($this->getServer()))
               ->setId($token)
               ->setExpireTime((int)$expireTime);
    }

    /**
      * {@inheritdoc}
      */
    public function associateScope(AccessTokenEntity $token, ScopeEntity $scope)
    {
        DB::collections('oauth_sessions')
            ->where('access_token.id', $token)
            ->push('access_token.scopes', [
                'id'        => $scope->getId(),
                'created_at'      => Carbon::now(),
            ]);
    }

    /**
      * {@inheritdoc}
      */
    public function delete(AccessTokenEntity $token)
    {
        DB::collections('oauth_sessions')
            ->where('access_token.id', $token->getId())
            ->unset('access_token');
    }
}
