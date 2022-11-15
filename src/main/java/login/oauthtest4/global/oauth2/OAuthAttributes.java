package login.oauthtest4.global.oauth2;

import login.oauthtest4.domain.user.Role;
import login.oauthtest4.domain.user.SocialType;
import login.oauthtest4.domain.user.User;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;
import java.util.UUID;

/**
 * 각 소셜에서 받아오는 데이터가 다르므로
 * 소셜별로 데이터를 받는 데이터를 분기 처리하는 DTO 클래스
 */
@Getter
public class OAuthAttributes {

    private Map<String, Object> attributes; // 소셜 로그인에서 API가 제공하는 userInfo의 Json 값
    private String nameAttributeKey; // OAuth2 로그인 진행 시 키가 되는 필드 값, PK와 같은 의미
    private String id; //소셜 식별 값 : 구글 - "eamil", 카카오 - "kakaoId", 네이버 - "id"

    private static final String NAVER_NAME_ATTRIBUTE_KEY = "id";

    @Builder
    public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String id) {
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
        this.id = id;
    }

    /**
     * SocialType에 맞는 메소드 호출하여 OAuthAttributes 객체 반환
     * 파라미터 : userNameAttributeName -> OAuth2 로그인 시 키(PK)가 되는 값 / attributes : OAuth 서비스의 유저 정보들
     * 소셜별 of 메소드(ofGoogle, ofKaKao, ofNaver)들은 각각 소셜 로그인 API에서 제공하는
     * 회원의 식별값(id), attributes, nameAttributeKey를 저장 후 build
     */
    public static OAuthAttributes of(SocialType socialType, String userNameAttributeName, Map<String, Object> attributes) {

        if (socialType == SocialType.NAVER) {
            return ofNaver(NAVER_NAME_ATTRIBUTE_KEY, attributes);
        }
        if (socialType == SocialType.KAKAO){
            return ofKakao(userNameAttributeName,attributes);
        }
        return ofGoogle(userNameAttributeName, attributes);
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .id(attributes.get("id") + "")
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .build();
    }

    public static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .id((String) attributes.get("email"))
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .build();
    }

    public static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        return OAuthAttributes.builder()
                .id((String) response.get("id"))
                .attributes(response)
                .nameAttributeKey(userNameAttributeName)
                .build();
    }

    /**
     * of메소드로 만든 OAuthAttributes 객체 정보들을 이용하여 현재 필드 값에 값들이 들어간 상태
     * id 필드값 이용하여 domain의 User 객체에 식별 값 저장 후 build
     * email에는 UUID로 중복 없는 랜덤 값 생성
     * role은 GUEST로 설정
     */
    public User toEntity(SocialType socialType) {
        return User.builder()
                .socialType(socialType)
                .socialId(id)
                .email(UUID.randomUUID().toString() + "@socialUser.com")
                .role(Role.GUEST)
                .build();
    }
}
