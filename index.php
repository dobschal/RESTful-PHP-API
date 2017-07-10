<?php

header("Access-Control-Allow-Orgin: *");
header("Access-Control-Allow-Methods: *");
header("Content-Type: application/json");

include_once "config.php";



/**
 *  Retrieve information about request
 */
$path = "";
if(isset($_SERVER['PATH_INFO']))
    $path = trim($_SERVER['PATH_INFO']);
else if(isset($_GET["path"]))
    $path = "/".$_GET["path"];
else
    response(["error" => "Missing path."], 400);
$method  = $_SERVER['REQUEST_METHOD'];
$request = explode( '/', $path );
$input   = (array) json_decode(file_get_contents('php://input'),true);
if(count($request) < 2) response(["error" => "Request path is too short or missing."], 400);
if(count($request) > 3) response(["error" => "Request path is too long."], 400);
$table = $request[ 1 ];
$key = count($request) === 3 ? $request[ 2 ] : false;



/**
 *  Transform data, configured in config.php 
 */
if(isset($input))
{
    foreach ($input as $key2 => $value)
    {
        if(isset($config["resources"][$table], $config["resources"][$table]["transform"], $config["resources"][$table]["transform"][$key2]))
        {
            $input[ $key2 ] = $config["resources"][$table]["transform"][$key2]( $value );
        }
    }
}



/**
 *  Authentication
 */
$user = [];
if($table === "auth")
{
    $id = $input["username"];
    $password = $config["resources"]["user"]["transform"][ "password" ]( $input["password"] );
    $user = getArrayFromFile( getFileName( "user", $id ) );
    if($user["password"] !== $password) 
        response(["error" => "Wrong credentials."], 401);
    else 
    {
        $token = base64_encode( json_encode($user) ).".".base64_encode( hash("SHA256", json_encode( $user ).$config["secret"] ) );
        setcookie("auth_token", $token);
        response([ "success" => "Authentication successfull.", "X-Auth-Token" => $token ], 200);
    }
}
else
{
    if(isset($_COOKIE["auth_token"]) || isset( $_SERVER["HTTP_X_AUTH_TOKEN"]))
    {
        $token = isset($_COOKIE["auth_token"]) ? $_COOKIE["auth_token"] : $_SERVER["HTTP_X_AUTH_TOKEN"];
        $token_parts = explode(".", $token);
        if(count($token_parts) !== 2) 
            response(["error" => "Permission denied. Invalid token."], 401);        
        $jsonUserString = base64_decode( $token_parts[0] );
        if(hash("SHA256", $jsonUserString.$config["secret"] ) !== base64_decode( $token_parts[1] ) ) 
            response(["error" => "Permission denied. Invalid token signature."], 401);
        $user = (array) json_decode( $jsonUserString );
    }   
}



/**
 *  Setup database
 */
makeDirIfNotExist("/data");
if(!file_exists("data/.htaccess"))
{    
    $createdHTAccess = file_put_contents(__DIR__."/data/.htaccess", "deny from all", LOCK_EX);
    if(!$createdHTAccess) response(["error" => "Could not setup database!"], 500);
}



/**
 *  Check permission of user
 */
if(!isset($config["resources"][$table]))
{
    response(["error" => "Unknown resource '{$table}'."], 404);
}
else
{
    $user["isOwner"] = $key && $method !== "POST" ? getArrayFromFile( getFileName( $table, $key ) )["_ownerId"] === $user["id"] : false;
    $user = (object) $user;
    $body = (object) $input;
    if(!$config["resources"][$table]["permission"]( $user, $body, $method ))
    {
        response(["error" => "Permission denied."], 401);
    }
}



/**
 *  Handle File Upload
 */
if(isset($_FILES["upfile"]))
{
    makeDirIfNotExist("/files");
    makeDirIfNotExist( "/data/files" );
    if (!isset($_FILES[ $config["uploadFileKey"] ]['error']) || is_array($_FILES[ $config["uploadFileKey"] ]['error']))
        response(["error" => 'Invalid parameters.'], 400);
    switch ($_FILES[$config["uploadFileKey"]]['error'])
    {
        case UPLOAD_ERR_OK: break;
        case UPLOAD_ERR_NO_FILE:
            response(["error" => 'No file sent.'], 400);
        case UPLOAD_ERR_INI_SIZE: 
        case UPLOAD_ERR_FORM_SIZE:
            response(["error" => 'Exceeded filesize limit.'], 400);
        default:
            response(["error" => 'Unknown errors.'], 400);
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    if (false === $ext = array_search(
        $finfo->file($_FILES[$config["uploadFileKey"]]['tmp_name']),
        $config["uploadAllowedTypes"],
        true
    ))
        response(["error" => 'Invalid file format.'], 400);
    $id = uniqid();
    $filename = sprintf( 'files/%s.%s', $id, $ext );
    if(!file_put_contents( getFileName("files", $id), json_encode([
        "id" => $id,
        "path" => $filename,
        "_timestamp" => time(),
        "_ownerId" => $user->id
    ], JSON_PRETTY_PRINT)))
        response(["error" => "Could not save database record for file."], 500);
    if (!move_uploaded_file( $_FILES[$config["uploadFileKey"]]['tmp_name'], $filename ))
        response(["error" => 'Failed to move uploaded file.'], 500);
    response(["success" => "File saved.", "filename" => $filename], 200);
}



/**
 *  Switch HTTP method and handle request
 */
switch ($method) {
	case 'GET':
	    if($key)
	    {
            response( getArrayFromFile( getFileName( $table, $key ) ), 200);
        }
        else
        {
            $filenames = glob(__DIR__."/data/{$table}/*.json");
            function mapFunc( $filename )
            {
                return getArrayFromFile( $filename );
            }
            response(array_map("mapFunc", $filenames), 200);
        }
    break;
	case 'PUT':
	    if($key)
	    {
            $filename = getFileName( $table, $key );
            $data = getArrayFromFile( $filename );
            if(!isset($input["_timestamp"]))
                response(["error" => "Missing timestamp on data."], 400);
            $input["_ownerId"] = $data["_ownerId"];
            if($data["_timestamp"] !== $input["_timestamp"]) 
                response(["error" => "Inkonsistent state of data between client and server."], 409);
            foreach ($input as $key => $value) 
                $data[ $key ] = $value;  
            $data["_timestamp"] = time();

            if(file_put_contents( $filename, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX ) === FALSE)
                response(["error" => "Could not update data."], 500);
            else
                response(["success" => "Data updated."], 200);
        }
        else
        {
            response(["error" => "Data key missing."], 400);
        }
	break;
	case 'POST':
        if($key)
	    {
            $filename = getFileName($table, $key);
            makeDirIfNotExist( "/data/{$table}" );
            if(!isset($input["id"]) || $input["id"] !== $key )
                $input["id"] = $key;
            $input["_ownerId"] = isset($user->id) ? $user->id : $input["id"];
            $input["_timestamp"] = time();            
            if(file_exists($filename)) response(["error" => "File already exists."], 409);
            if(file_put_contents( $filename, json_encode($input, JSON_PRETTY_PRINT), LOCK_EX ) === FALSE)
                response(["error" => "Could not create data."], 500);
            else
                response(["success" => "Data created."], 200);
        }
        else
        {
            response(["error" => "Data key missing."], 400);
        }
	break;
	case 'DELETE':
	    if($key)
	    {
            $filename = getFileName($table, $key);
            if(!file_exists($filename)) response(["error" => "File not found."], 404);
            if (!unlink($filename))
            {
                response(["error" => "Could not delete data."], 500);
            }
            else
            {
                response(["success" => "Data deleted."], 200);
            }            
        }
        else
        {
            response(["error" => "Data key missing."], 400);
        }
	break;
    default:
        response(["error" => "Unkown method."], 400);
    break;
}



/**
 *  End script with an http response code header and
 *  and an json encoded body.
 *  @param Array $body
 *  @param integer $code
 *  @return void
 */
function response( $body, $code = 200 )
{
    http_response_code( $code );
    die( json_encode($body) );
}



/**
 *  Read database file with filename and 
 *  returns array of data.
 *  @param string $filename
 *  @return void
 */
function getArrayFromFile( $filename )
{
    if(!file_exists($filename)) response(["error" => "File '{$filename}' not found."], 404);
    return (array) json_decode( file_get_contents($filename) );
}


/**
 *  Retrieve the filename for the database 
 *  entry by table and key.
 *  @param string $table
 *  @param string $key
 *  @return void
 */
function getFileName( $table, $key )
{
    return __DIR__."/data/{$table}/{$key}.json";
}



/**
 *  Check if the given path exist, if not 
 *  create the directory
 *  @param string $path
 *  @return void
 */
function makeDirIfNotExist( $path )
{
    if(!file_exists(__DIR__.$path))
    {
        $oldmask = umask(0);
        $makedDir = mkdir(__DIR__.$path, 0777);
        umask($oldmask); 
        if(!$makedDir) response(["error" => "Could not create directory '{$path}'!"], 500);
    }
}