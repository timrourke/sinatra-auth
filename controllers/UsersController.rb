class UsersController < ApplicationController

	def does_user_exist?(email)
		@user = User.find_by(:user_email => email.downcase.to_s )

		if @user
			return true
		else
			return false
		end
	end

	def confirmation_link_valid?(user)
		if user.email_confirmation_expiry > Time.now
			return true
		else
			return false
		end
	end

	def send_email_confirm_message(email_address, email_confirmation_route)
		#takes configuration as set in ./.config/mail_configuration.rb
		Pony.mail({
		  :to => email_address.to_s,
		  :from => MAIL_FROM_ADDRESS,
		  :via => :smtp,
		  :via_options => {
		    :address        => MAIL_PROVIDER_HOST_ADDRESS,
		    :port           => MAIL_PROVIDER_HOST_PORT,
		    :enable_starttls_auto => true,
		    :user_name      => MAIL_USER_NAME,
		    :password       => MAIL_PASSWORD,
		    :authentication => :plain, # :plain, :login, :cram_md5, no auth by default
		    :domain         => "localhost.localdomain", # the HELO domain provided by the client to the server
		    :arguments			=> ''
		  },
		  :html_body => "<h1>Welcome to Sinatra-Auth.</h1><p>Thanks for registering!</p> <br> <p>Go to <a href='#{email_confirmation_route}'>this link</a> to confirm your email address and create your account.</p><p>-The team at Sinatra-Auth</p>"
		})
	end

	get '/' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)
		@users = User.order("lower(user_name) DESC").all

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
				if (user.email_confirmed == '1')
					#success, render success template
					session[:user] = user
					@user = session[:user]
					
					erb :'users/thanks-login', :locals => {'body_class' => 'users users--login'}
				else
					#fallback error
					session[:user] = nil
					@user = nil
					flash.message = "Your email has not been verified. Please check your email for the confirmation link or request a new confirmation email below."

					@request_new_email_confirmation_link = "<p><a href='/users/request-new-confirmation-email'>Request a new confirmation email.</a></p>"

					erb :'users/login', :locals => {'body_class' => 'users users--login'}
				end

			else
				#fallback error
				session[:user] = nil
				@user = nil
				flash.message = "Your username or password were incorrect. Please try again."
				erb :'users/login', :locals => {'body_class' => 'users users--login'}
			end

		end
	end

	post '/signup' do
		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem adding you as a user. Please try again."
			erb :'users/signup', :locals => {'body_class' => 'users users--signup'}

		elsif self.does_user_exist?(params[:user_email].downcase)
			#return early if user already exists
			flash.message = "Sorry, this email address is already registered. Please use a unique email address."
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
			@new_user.created = Time.now
			@new_user.email_confirmed = 0
			@new_user.email_confirmation_route = SecureRandom.uuid
			@new_user.email_confirmation_expiry = Time.now + 30*60

			@email_destination = @new_user.user_email
			#TODO: remove port in production, or otherwise normalize req uri
			@confirmation_route = request.host + ':' + request.port.to_s + '/users/confirm-email/' + @new_user.email_confirmation_route

			password_salt = BCrypt::Engine.generate_salt
			password_hash = BCrypt::Engine.hash_secret(params[:user_password], password_salt)

			@new_user.password_salt = password_salt
			@new_user.password_hash = password_hash

			if @new_user.save

				send_email_confirm_message(@email_destination, @confirmation_route)

				erb :'users/thanks-signup', :locals => {'body_class' => 'users users--signup'}
			else
				flash.message = "Sorry, there was a problem creating you as a user. Please try again."
				erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
			end
		end
	end

	get '/edit/:id' do
		authorization_check

		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

		@user = User.find(params[:id])

		if @user
			erb :'users/edit', :locals => {'body_class' => 'users users--edit'}
		else
			redirect not_found
		end
	end

	post '/edit' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			@user = @edited_user
			flash.message = "Sorry, there was a problem editing the user. Please try again."
			erb :'users/edit', :locals => {:id => params[:user_id], 'body_class' => 'users users--edit'}
		
		else
			@edited_user = User.find(params[:user_id])
			@edited_user.user_name = params[:user_name]
			@edited_user.user_email = params[:user_email].downcase
			@edited_user.is_admin = (params[:user_is_admin]) ? 1 : 0 #0 is false, 1 is true
			@edited_user.modified = Time.now

			if @edited_user.save
				@user = @edited_user
				flash.message = "You have successfully edited the user."
				erb :'users/edit', :locals => {:id => params[:user_id], 'body_class' => 'users users--edit'}
			else
				@user = @edited_user
				flash.message = "Sorry, there was a problem editing the user. Please try again."
				erb :'users/edit', :locals => {:id => params[:user_id], 'body_class' => 'users users--edit'}
			end
		end

	end

	get '/new' do
		authorization_check

		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

		erb :'users/new', :locals => {'body_class' => 'users users--new'}	
	end

	post '/new' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem creating the user. Please try again."
			erb :'users/new', :locals => {'body_class' => 'users users--new'}
		
		elsif (params[:user_password].to_s != params[:user_password_confirm].to_s)
			#return early if password doesn't match confirmation password
			flash.message = "Your passwords did not match. Please try again."
			erb :'users/new', :locals => {'body_class' => 'users users--new'}
		
		else
			@new_user = User.new
			@new_user.user_name = params[:user_name]
			@new_user.user_email = params[:user_email].downcase
			@new_user.is_admin = 0 #0 is false, 1 is true
			@new_user.created = Time.now

			password_salt = BCrypt::Engine.generate_salt
			password_hash = BCrypt::Engine.hash_secret(params[:user_password], password_salt)

			@new_user.password_salt = password_salt
			@new_user.password_hash = password_hash

			if @new_user.save
				@users = User.order("lower(user_name) DESC").all
				flash.message = "Success! You have created a new user."
				erb :'users', :locals => {'body_class' => 'users users--new'}
			else
				flash.message = "Sorry, there was a problem creating the user. Please try again."
				erb :'users/new', :locals => {'body_class' => 'users users--new'}
			end
		end

	end

	post '/delete' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])

		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem deleting the user. Please try again."
			redirect back
		else
			@user = User.find(params[:user_id])
			#TODO: create deletion confirmation message if user tries to delete themself
			#make sure to implement js version on frontend, and be sure to log user out.
			#ensure user deleting self must resupply email and password to destroy self.
			if @user && @user.destroy
				flash.message = "Success! You have destroyed a user."
				@users = User.order("lower(user_name) DESC").all
				erb :'users', :locals => {'body_class' => 'users'}
			else
				flash.message = "Sorry, there was a problem deleting the user. Please try again."
				@users = User.order("lower(user_name) DESC").all
				erb :'users', :locals => {'body_class' => 'users'}
			end
		end
	end

	get '/confirm-email/:uuid' do
		@user = User.find_by(:email_confirmation_route => params[:uuid])

		if @user
			if @user.email_confirmed == '1'
				#user already confirmed, redirect to login page.
				flash.message = "You have already confirmed your email. You may now log in."
				erb :'users/login', :locals => {'body_class' => 'users users--login'}
			elsif confirmation_link_valid?(@user)
				#if confirmation link has not expired, save user as now confirmed.
				#also delete confirmation route from user to prevent retrying.
				@user.email_confirmed = 1
				@user.email_confirmation_route = ""
				if @user.save
					#success, save user.
					flash.message = "Success! You have successfully confirmed your email. You may now log in."
					erb :'users/login', :locals => {'body_class' => 'users users--login'}
				else
					#couldn't save user.
					flash.message = "Sorry, there was a problem registering your email address. Please check that the link you supplied was correct."
					erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
				end
			else
				#confirmation link has expired.
				flash.message = "Sorry, there was a problem registering your email address. Please check that the link you supplied was correct."
				erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
			end
		else
			#user not found by uuid.
			flash.message = "Sorry, there was a problem registering your email address. Please check that the link you supplied was correct."
			erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
		end
	end

	get '/request-new-confirmation-email' do

		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

		erb :'users/request-new-confirmation-email', :locals => {'body_class' => 'users users--request-new-confirmation-email'}
	end

	post '/request-new-confirmation-email' do

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])

		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem deleting the user. Please try again."
			redirect back
		else
			@user = User.find_by(:user_email => params[:user_email])

			if @user
				if @user.password_hash == BCrypt::Engine.hash_secret(params[:user_password], @user.password_salt)
					@user.modified = Time.now
					@user.email_confirmed = 0
					@user.email_confirmation_route = SecureRandom.uuid
					@user.email_confirmation_expiry = Time.now + 30*60

					@email_destination = @user.user_email
					#TODO: remove port in production, or otherwise normalize req uri
					@confirmation_route = request.host + ':' + request.port.to_s + '/users/confirm-email/' + @user.email_confirmation_route

					if @user.save

						send_email_confirm_message(@email_destination, @confirmation_route)

						erb :'users/thanks-signup', :locals => {'body_class' => 'users users--signup'}
					else
						flash.message = "Sorry, there was a problem sending you a new account confirmation email. Please try again."
						redirect back
					end
				else 
					flash.message = "Your username or password were incorrect. Please try again."

					#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
					@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

					redirect back
				end
			else
				flash.message = "Your username or password were incorrect. Please try again."

				#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
				@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

				redirect back
			end


		end
	end

end