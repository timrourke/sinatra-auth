require 'sinatra/base'

# Enable sessions, and set secrets for Rack sessions and Rack nonce
Dir.glob('./.config/*.rb').each{
	|file| require file
}

# Load all controllers and models
Dir.glob('./{controllers,models}/*.rb').each{
	|file| require file
}

map('/') { run HomeController }
map('/users') { run UsersController }