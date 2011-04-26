module Rack
  module OAuth2
    class Server     
          
      class Client < Sequel::Model(:clients)
        unrestrict_primary_key

        class << self
          # Authenticate a client request. This method takes three arguments
          # Find Client from client identifier.
          def find(client_id)
            self[:id => client_id]
          end
          
          def by_identity identity
            self.filter(:identity => identity)
          end

          # Create a new client. Client provides the following properties:
          # # :display_name -- Name to show (e.g. UberClient)
          # # :link -- Link to client Web site (e.g. http://uberclient.dot)
          # # :image_url -- URL of image to show alongside display name
          # # :redirect_uri -- Registered redirect URI.
          # # :scope -- List of names the client is allowed to request.
          # # :notes -- Free form text.
          # 
          # This method does not validate any of these fields, in fact, you're
          # not required to set them, use them, or use them as suggested. Using
          # them as suggested would result in better user experience.  Don't ask
          # how we learned that.
          def create(args)
            puts args.to_json
            redirect_uri = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
            scope = Server::Utils.normalize_scope(args[:scope])
             
            fields                = args
            fields[:scope]        = scope
            fields[:created_at]   = Time.now
            fields[:revoked]      = nil
            fields[:redirect_uri] = redirect_uri
            
            if args[:id] && args[:secret]
              fields[:id], fields[:secret] = args[:id].to_s, args[:secret]
            else
              fields[:secret] = Server.secure_random
              fields[:id] = Server.secure_random[0..16]
            end
            
            super( fields )
          end

          # Lookup client by ID, display name or URL.
          #def lookup(field)
          #  id = BSON::ObjectId(field.to_s)
          #  Server.new_instance self, collection.find_one(id)
          #rescue BSON::InvalidObjectId
          #  Server.new_instance self, collection.find_one({ :display_name=>field }) || collection.find_one({ :link=>field })
          #end

          # Returns all the clients in the database, sorted alphabetically.
          def all
            collection.all.order(:display_name)
          end

          # Deletes client with given identifier (also, all related records).
          def delete(client_id)
            
            self[client_id].delete
            AuthRequest.collection.remove({ :client_id=>id })
            AccessGrant.collection.remove({ :client_id=>id })
            AccessToken.collection.remove({ :client_id=>id })
          end

          def collection
            Server.database
          end
          
        end #end of static stuff
        
        
        def scope
          JSON.parse( self[:scope] )
        end
        
        
        def token_granted
          self[:tokens_granted] = self[:tokens_granted] + 1;
          puts "new grant count: #{self[:tokens_granted]} "
          self.save
        end
        
        def token_revoked
          self[:tokens_revoked] = self[:tokens_revoked] + 1;
          self.save
        end

        # Revoke all authorization requests, access grants and access tokens for
        # this client. Ward off the evil.
        def revoke!
          self.revoked = Time.now
          self.save
          
          #TODO: update as other models are changed to use sequel
          AuthRequest.collection.update({ :client_id=>id }, { :$set=>{ :revoked=>revoked } })
          AccessGrant.collection.update({ :client_id=>id }, { :$set=>{ :revoked=>revoked } })
          AccessToken.collection.update({ :client_id=>id }, { :$set=>{ :revoked=>revoked } })
        end

        def update(args)
          fields = [:display_name, :link, :image_url, :notes].inject({}) { |h,k| v = args[k]; h[k] = v if v; h }
          fields[:redirect_uri] = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
          fields[:scope] = Server::Utils.normalize_scope(args[:scope])
          
          collection[:id => id].update(fields)
        end
      end

    end
  end
end
