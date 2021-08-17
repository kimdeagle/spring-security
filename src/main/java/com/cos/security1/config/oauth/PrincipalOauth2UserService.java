package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : "+userRequest.getClientRegistration()); //registrationId로 어떤 oauth로 로그인 했는지 확인 가능
        System.out.println("getAccessToken : "+userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        //구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code 리턴(OAuth Client Library) -> AccessToken 요청
        //userRequest 정보 -> loadUser 함수 호출 -> 회원 프로필 조회
        System.out.println("getAttributes : "+oAuth2User.getAttributes());

        //회원가입 진행
        OAuth2UserInfo oAuth2UserInfo = null;
        if (StringUtils.equals(userRequest.getClientRegistration().getRegistrationId(), "google")) {
            System.out.println("구글");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (StringUtils.equals(userRequest.getClientRegistration().getRegistrationId(), "facebook")) {
            System.out.println("페이스북");
            //oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (StringUtils.equals(userRequest.getClientRegistration().getRegistrationId(), "naver")) {
            System.out.println("네이버");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId; //ex) google_120315157019
        String password = bCryptPasswordEncoder.encode("겟인데어"); //의미 없음
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (ObjectUtils.isEmpty(userEntity)) {
            //회원가입
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
