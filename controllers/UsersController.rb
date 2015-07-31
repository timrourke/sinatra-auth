class UsersController < ApplicationController

	def does_user_exist?(email)
		user = User.find_by(:user_email => email.downcase.to_s )

		if user
			return true
		else
			return false
		end
	end

	get '/' do
		authorization_check

		erb :users, :locals => {'body_class' => 'users'}
	end

	get '/login' do
		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)
		erb :'users/login', :locals => {'body_class' => 'users users--login'}
	end

	get '/signup' do
		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)
		@user = session[:user]
		erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
	end

	get '/logout' do
		session[:user] = nil
		redirect '/'
	end

	post '/login' do
		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		if (!@nonce.valid? && @nonce.stale?)
			#return early if nonce bad/stale
			flash.message = "There was a problem with your login Please try again."
			erb :'users/login', :locals => {'body_class' => 'users users--login'}
	
		elsif (self.does_user_exist?(params[:user_email].downcase) != true)
			#return early if user does not exist
			flash.message = "Your username or password were incorrect. Please try again."
			erb :'users/login', :locals => {'body_class' => 'users users--login'}

		else
			#no user errors detected
			user = User.where(:user_email => params[:user_email].downcase).first!

			if user.password_hash == BCrypt::Engine.hash_secret(params[:user_password], user.password_salt)
				#success, render success template
				session[:user] = user
				puts 'SUCCESSSSSSSSSSS!!!!!'
				@user = session[:user]
				
				erb :'users/thanks-login', :locals => {'body_class' => 'users users--login'}

			else
				#fallback error
				flash.message = "Your username or password were incorrect. Please try again."
				erb :'users/login', :locals => {'body_class' => 'users users--login'}
			end

		end
	end

	post '/signup' do
		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem logging you in. Please try again."
			erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
		
		elsif (params[:user_password].to_s != params[:user_password_confirm].to_s)
			#return early if password doesn't match confirmation password
			flash.message = "Your passwords did not match. Please try again."
			erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
		
		else
			@new_user = User.new
			@new_user.user_name = params[:user_name]
			@new_user.user_email = params[:user_email].downcase
			@new_user.is_admin = 0 #0 is false, 1 is true

			password_salt = BCrypt::Engine.generate_salt
			password_hash = BCrypt::Engine.hash_secret(params[:user_password], password_salt)

			@new_user.password_salt = password_salt
			@new_user.password_hash = password_hash

			if @new_user.save
				erb :'users/thanks-signup', :locals => {'body_class' => 'users users--signup'}
			else
				flash.message = "Sorry, there was a problem creating you as a user. Please try again."
				erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
			end
		end
	end


end