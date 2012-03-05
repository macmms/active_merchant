require 'test_helper'

class PaypalRecurringTest < Test::Unit::TestCase
  def setup
    Base.gateway_mode = :test
    
    
    @gateway = PaypalGateway.new(fixtures(:paypal_signature))

    @creditcard = CreditCard.new(
      :type                => "visa",
      :number              => "4210835615182844", # Use a generated CC from the paypal Sandbox
      :verification_value => "123",
      :month               => "02",
      :year                => "2017",
      :first_name          => "Siyuan",
      :last_name           => "He"
    )
       
    @params = {
      :order_id => generate_unique_id,
      :email => 'buyer@jadedpallet.com',
      :billing_address => { :name => 'Fred Brooks',
                    :address1 => '1234 Penny Lane',
                    :city => 'Jonsetown',
                    :state => 'NC',
                    :country => 'US',
                    :zip => '23456'
                  } ,
      :description => 'Stuff that you purchased, yo!',
      :ip => '10.0.0.1'
    }
      
    @amount = 100
    # test re-authorization, auth-id must be more than 3 days old.
    # each auth-id can only be reauthorized and tested once.
    # leave it commented if you don't want to test reauthorization.
    # 
    #@three_days_old_auth_id  = "9J780651TU4465545" 
    #@three_days_old_auth_id2 = "62503445A3738160X" 
  end

  def test_successful_create_profile
    options = { :description => "this is test description",
                :credit_card => @creditcard,
                :start_date => Time.parse("2017-02-17 00:00:00").getutc,
                :frequency => 1,
                :amount => 1 }


    response = @gateway.create_profile( nil, options)
    assert_success response
    assert response.params['ProfileID']
    assert_equal "ActiveProfile", response.params['ProfileStatus']

  end

  def test_successful_suspend_profile
    options = { :description => "this is test description",
                :credit_card => @creditcard,
                :start_date => Time.parse("2017-02-17 00:00:00").getutc,
                :frequency => 1,
                :amount => 1 }


    response = @gateway.create_profile( nil, options)
    profileID = response.params['ProfileID']
    response2 = @gateway.suspend_profile( profileID, options )
    assert "Suspend", response.params['ProfileID']
  end

  def test_successful_get_credit_card_info_after_suspend
    options = { :description => "this is test description",
                :credit_card => @creditcard,
                :start_date => Time.parse("2017-02-17 00:00:00").getutc,
                :frequency => 1,
                :amount => 1 }


    response = @gateway.create_profile( nil, options)
    profileID = response.params['ProfileID']
    @gateway.suspend_profile( profileID, options )
    response = @gateway.get_profile_details( profileID)
    assert response.params['CreditCard']
    assert_equal "2844", response.params['CreditCard']['CreditCardNumber']
  end


end