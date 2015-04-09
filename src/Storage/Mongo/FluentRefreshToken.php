<?php
/**
 * Fluent storage implementation for an OAuth 2.0 Refresh Token
 *
 * @package   lucadegasperi/oauth2-server-laravel
 * @author    Luca Degasperi <luca@lucadegasperi.com>
 * @copyright Copyright (c) Luca Degasperi
 * @licence   http://mit-license.org/
 * @link      https://github.com/lucadegasperi/oauth2-server-laravel
 */

namespace LucaDegasperi\OAuth2Server\Storage\Mongo;

use League\OAuth2\Server\Storage\RefreshTokenInterface;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use Carbon\Carbon;

class FluentRefreshToken extends FluentAdapter implements RefreshTokenInterface
{
    /**
     * Return a new instance of \League\OAuth2\Server\Entity\RefreshTokenEntity
     * @param  string $token
     * @return \League\OAuth2\Server\Entity\RefreshTokenEntity
     */
    public function get($token)
    {

        $result = DB::collection('oauth_sessions')
            ->where('access_token.refresh.id', $token)
            ->where('access_token.refresh.expire_time', '>=', time())
            ->select('acces_token')
            ->first();

        if (is_null($result)) {
            return null;
        }

        return (new RefreshTokenEntity($this->getServer()))
               ->setId($result['refresh']['id'])
               ->setAccessTokenId($result['id'])
               ->setExpireTime((int)$result['refresh']['expire_time']);
    }

    /**
     * Create a new refresh token_name
     * @param  string $token
     * @param  integer $expireTime
     * @param  string $accessToken
     * @return \League\OAuth2\Server\Entity\RefreshTokenEntity
     */
    public function create($token, $expireTime, $accessToken)
    {
        DB::collection('oauth_sessions')
        ->where('access_token.id', $accessToken)
        ->update([
            'access_token.refresh' => [
                'id'              => $token,
                'expire_time'     => $expireTime,
                'created_at' => Carbon::now(),
            ]
        ]);

        return (new RefreshTokenEntity($this->getServer()))
               ->setId($token)
               ->setAccessTokenId($accessToken)
               ->setExpireTime((int)$expireTime);
    }

    /**
     * Delete the refresh token
     * @param  \League\OAuth2\Server\Entity\RefreshTokenEntity $token
     * @return void
     */
    public function delete(RefreshTokenEntity $token)
    {
        DB::collection('oauth_sessions')
            ->where('access_token.refresh.id', $token->getId())
            ->unset('access_token.refresh');
    }
}
