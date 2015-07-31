class ApplicationController < Sinatra::Base
	require 'bundler'
	Bundler.require()

	
	enable :sessions
	
  
  #Implement flash messages
	class FlashMessage
	  def initialize(session)
	    @session ||= session
	  end

	  def message=(message)
	    @session[:flash] = message
	  end

	  def message
	    message = @session[:flash] #tmp get the value
	    @session[:flash] = nil # unset the value
	    message # display the value
	  end
	end

	helpers do
	  def flash
	    @flash ||= FlashMessage.new(session)
	  end
	end

	ActiveRecord::Base.establish_connection(
		:adapter	=> 'postgresql',
		:database	=> 'sinatra_auth'
	)

	set :views, File.expand_path('../../views', __FILE__)
	set :public_folder, File.expand_path('../../public', __FILE__)

	not_found do
		erb :not_found, :locals => {'body_class' => 'not-found'}
	end

	 def is_authenicated?
    if session[:user].nil? == true
      return false
    else
      return true
    end
  end

  def current_user
    return session[:user]
  end

  def authorization_check
    if is_authenicated? == false
      redirect '/not_authenticated'
    end
  end

end