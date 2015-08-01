require 'sinatra/base'

# Load all controllers and models
Dir.glob('./{controllers,models}/*.rb').each{
	|file| require file
}

map('/') { run HomeController }
map('/users') { run UsersController }