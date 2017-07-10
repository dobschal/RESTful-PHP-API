<?php
$config =
[
    "uploadFileKey" => "upfile",
    "uploadAllowedTypes" => [
        'jpg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
    ],
    "secret" => "9db6783696b48dd87bee73135134b4bffe6a1c66814415d231",
    "resources" =>
    [
        "user" => 
        [
            "permission" => function( $user, $body, $method )
            {
                switch ($method) {
                    case 'GET': return $user->isOwner;
                    case 'POST': return $body->role === "USER";
                    case 'PUT': return $user->role === "ADMIN";
                    case 'DELETE': return $user->role === "ADMIN";
                    default: return true;
                }
            },
            "transform" => 
            [ 
                "password" => function( $oldValue, $isRequest )
                {
                    if($isRequest)
                        return hash( "SHA512", $oldValue );
                    else
                        return "";
                }
            ]
        ],
        "files" => [

            /**
             *  Standard permission:
             *  Everybody can read
             *  Authorized users can create
             *  Owners can update or delete
             */
            "permission" => function( $user, $body, $method)
            {
                switch ($method) {
                    case "POST": return isset($user->id);
                    case 'PUT': return $user->isOwner;
                    case 'DELETE': return $user->isOwner;
                    default: return true;
                }
            }
        ],
        "article" => 
        [
            "permission" => function( $user, $body, $method )
            {
                switch ($method) {
                    case "POST": return isset($user->id);
                    case 'PUT': return $user->isOwner;
                    case 'DELETE': return $user->isOwner;
                    default: return true;
                }
            }
        ]
    ]
];